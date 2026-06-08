import crypto from 'crypto'
import fs from 'fs'
import http from 'http'
import https from 'node:https'
import path from 'path'
import { Transform } from 'stream'

import { applyZipResponseHeaders } from './zipPackageEnc'

const CACHE_DIR = path.join(process.cwd(), 'conf', 'cache', 'zip-raw')
const activeEntries = new Map()

function ensureDir() {
  fs.mkdirSync(CACHE_DIR, { recursive: true })
}

function safeId(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex')
}

function cachePaths(id) {
  ensureDir()
  return {
    finalPath: path.join(CACHE_DIR, `${id}.zip`),
    partPath: path.join(CACHE_DIR, `${id}.part`),
  }
}

function ensurePartFile(entry) {
  ensureDir()
  if (!fs.existsSync(entry.partPath)) {
    fs.closeSync(fs.openSync(entry.partPath, 'w'))
  }
}

function mergeSegments(segments, start, end) {
  if (end < start) return segments
  const next = [...segments, [start, end]].sort((a, b) => a[0] - b[0])
  const merged = []
  for (const item of next) {
    const last = merged[merged.length - 1]
    if (!last || item[0] > last[1] + 1) {
      merged.push(item)
    } else if (item[1] > last[1]) {
      last[1] = item[1]
    }
  }
  return merged
}

function markCached(entry, start, end) {
  entry.segments = mergeSegments(entry.segments, start, end)
}

function hasRange(entry, start, end) {
  if (!entry || end < start) return false
  if (entry.complete) return true
  return entry.segments.some((item) => item[0] <= start && item[1] >= end)
}

function prefixEnd(entry) {
  const first = entry.segments.find((item) => item[0] === 0)
  return first ? first[1] : -1
}

function cleanHeaders(headers = {}) {
  const next = { ...headers }
  delete next.host
  delete next.Host
  delete next.range
  delete next.Range
  delete next['content-length']
  delete next['Content-Length']
  delete next['accept-encoding']
  delete next['Accept-Encoding']
  return next
}

function httpGet(urlAddr, headers, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const httpRequest = urlAddr.indexOf('https') === 0 ? https : http
    const req = httpRequest.get(urlAddr, { headers, rejectUnauthorized: false }, (resp) => {
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location && redirectCount < 5) {
        resp.resume()
        const nextUrl = new URL(resp.headers.location, urlAddr).toString()
        httpGet(nextUrl, headers, redirectCount + 1).then(resolve, reject)
        return
      }
      resolve(resp)
    })
    req.on('error', reject)
  })
}

function filePath(entry) {
  return entry.complete ? entry.finalPath : entry.partPath
}

export function zipCacheKey({ virtualPath, redirectUrl, fileSize, passwdInfo }) {
  return safeId(
    JSON.stringify({
      virtualPath,
      redirectUrl,
      fileSize,
      encType: passwdInfo && passwdInfo.encType,
      zipMode: passwdInfo && passwdInfo.zipMode,
      passwordHash: passwdInfo ? safeId(passwdInfo.password || '') : '',
    })
  )
}

export function getZipCacheEntry(id, totalSize) {
  if (!id || !totalSize) return null
  const existing = activeEntries.get(id)
  if (existing) return existing

  const { finalPath, partPath } = cachePaths(id)
  const entry = {
    id,
    totalSize: Number(totalSize) || 0,
    finalPath,
    partPath,
    complete: false,
    downloading: false,
    segments: [],
  }

  if (fs.existsSync(finalPath)) {
    const stat = fs.statSync(finalPath)
    if (stat.size === entry.totalSize) {
      entry.complete = true
      entry.segments = [[0, entry.totalSize - 1]]
    }
  }

  activeEntries.set(id, entry)
  return entry
}

export function canServeZipCacheRange(entry, range) {
  if (!entry || !range) return false
  return hasRange(entry, range.start, range.end)
}

export function attachZipCacheWrite(request, entry, range) {
  if (!entry || !range || request.method.toLocaleUpperCase() === 'HEAD') return
  request.zipCacheWrite = { entry, start: range.start }
}

export function createZipCacheWriteTransform({ entry, start }) {
  ensurePartFile(entry)
  const write = fs.createWriteStream(entry.partPath, { flags: 'r+', start })
  let offset = Number(start) || 0

  return new Transform({
    transform(chunk, encoding, next) {
      write.write(chunk, (err) => {
        if (!err) {
          markCached(entry, offset, offset + chunk.length - 1)
          offset += chunk.length
          this.push(chunk)
        }
        next(err)
      })
    },
    flush(next) {
      write.end(next)
    },
    destroy(err, callback) {
      write.destroy()
      callback(err)
    },
  })
}

export async function ensureZipCacheDownload(entry, urlAddr, headers = {}) {
  if (!entry || entry.complete || entry.downloading || !urlAddr) return
  let start = prefixEnd(entry) + 1
  if (start >= entry.totalSize) return

  entry.downloading = true
  ensurePartFile(entry)
  const requestHeaders = cleanHeaders(headers)
  requestHeaders.Range = `bytes=${start}-${entry.totalSize - 1}`

  try {
    const resp = await httpGet(urlAddr, requestHeaders)
    if (resp.statusCode !== 200 && resp.statusCode !== 206) {
      resp.resume()
      return
    }
    if (resp.statusCode === 200 && start > 0) {
      fs.truncateSync(entry.partPath, 0)
      entry.segments = []
      start = 0
    }
    const write = fs.createWriteStream(entry.partPath, { flags: 'r+', start })
    let offset = start
    resp.on('data', (chunk) => {
      markCached(entry, offset, offset + chunk.length - 1)
      offset += chunk.length
    })
    await new Promise((resolve, reject) => {
      resp.pipe(write)
      resp.on('error', reject)
      write.on('error', reject)
      write.on('finish', resolve)
    })
    if (hasRange(entry, 0, entry.totalSize - 1)) {
      entry.complete = true
      if (!fs.existsSync(entry.finalPath)) {
        fs.renameSync(entry.partPath, entry.finalPath)
      }
    }
  } catch (e) {
    entry.lastError = e.message
  } finally {
    entry.downloading = false
  }
}

export function startZipCacheDownload(entry, urlAddr, headers = {}) {
  ensureZipCacheDownload(entry, urlAddr, headers)
}

export function serveZipCacheRange(response, request, entry, decryptTransform) {
  const range = request.zipPackageRange
  response.setHeader('x-zip-cache', entry.complete ? 'hit-complete' : 'hit-partial')
  applyZipResponseHeaders(response, request)
  if (request.method.toLocaleUpperCase() === 'HEAD') {
    response.end()
    return Promise.resolve()
  }

  return new Promise((resolve, reject) => {
    const read = fs.createReadStream(filePath(entry), { start: range.start, end: range.end })
    read.on('error', reject)
    response.on('finish', resolve)
    response.on('close', () => {
      read.destroy()
      if (decryptTransform) decryptTransform.destroy()
    })
    if (decryptTransform) {
      read.pipe(decryptTransform).pipe(response)
    } else {
      read.pipe(response)
    }
  })
}
