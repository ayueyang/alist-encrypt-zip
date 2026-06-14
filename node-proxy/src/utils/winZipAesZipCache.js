import path from 'path'
import { cacheFileInfo, getFileInfo, getZipInfoCacheExpireSeconds, isZipInfoCacheEnabled } from '../dao/fileDao'
import levelDB from './levelDB'
import {
  isWinZipAesEncType,
  parseWinZipAesZipInfoFromRemote,
  serializeWinZipAesZipInfo,
} from './winZipAesZip'

const NEGATIVE_CACHE_SECONDS = 10 * 60
const PROBE_TABLE = 'winZipAesZipProbe_'
const probeQueue = []
const pendingKeys = new Set()
let probing = false

function normalizePath(filePath = '') {
  return decodeURIComponent(filePath)
}

function normalizeSize(size) {
  return Number(size) || 0
}

function probeKey(filePath) {
  return PROBE_TABLE + normalizePath(filePath)
}

export function isUsableWinZipAesZipInfoCache(fileInfo, size) {
  return !!(
    fileInfo &&
    fileInfo.zipInfo &&
    isWinZipAesEncType(fileInfo.zipInfo.encType) &&
    Number(fileInfo.size) === normalizeSize(size)
  )
}

export function isUsableWinZipAesZipNegativeCache(probeInfo, size) {
  return !!(
    probeInfo &&
    probeInfo.notPlayable &&
    Number(probeInfo.size) === normalizeSize(size)
  )
}

export async function getWinZipAesZipProbeCache(filePath, size, options = {}) {
  const cachedFileInfo = (await getFileInfo(filePath)) || (await getFileInfo(encodeURIComponent(filePath)))
  if (!options.ignoreInfoCache && isUsableWinZipAesZipInfoCache(cachedFileInfo, size)) {
    return { type: 'hit', fileInfo: cachedFileInfo }
  }
  const negativeProbe = await levelDB.getValue(probeKey(filePath))
  if (isUsableWinZipAesZipNegativeCache(negativeProbe, size)) {
    return { type: 'negative', probeInfo: negativeProbe, fileInfo: cachedFileInfo }
  }
  return { type: 'miss', fileInfo: cachedFileInfo }
}

export async function cacheExternalWinZipAesZipInfo(fileInfo, zipInfo, passwdInfo) {
  const nextFileInfo = {
    ...fileInfo,
    path: normalizePath(fileInfo.path),
    name: fileInfo.name || path.basename(fileInfo.path),
    size: normalizeSize(fileInfo.size),
    plainSize: zipInfo.plainSize,
    zipInfo: serializeWinZipAesZipInfo(zipInfo),
    externalZip: true,
    zipVirtualName: fileInfo.zipVirtualName || fileInfo.name || path.basename(fileInfo.path),
  }
  if (!isZipInfoCacheEnabled(passwdInfo)) return nextFileInfo
  await cacheFileInfo(nextFileInfo, getZipInfoCacheExpireSeconds(passwdInfo))
  return nextFileInfo
}

export async function cacheManagedWinZipAesZipInfo(fileInfo, zipInfo, passwdInfo) {
  const nextFileInfo = {
    ...fileInfo,
    path: normalizePath(fileInfo.path),
    name: fileInfo.name || path.basename(fileInfo.path),
    size: normalizeSize(fileInfo.size),
    plainSize: zipInfo.plainSize,
    zipInfo: serializeWinZipAesZipInfo(zipInfo),
    externalZip: false,
    zipVirtualName: fileInfo.zipVirtualName,
  }
  if (!isZipInfoCacheEnabled(passwdInfo)) return nextFileInfo
  await cacheFileInfo(nextFileInfo, getZipInfoCacheExpireSeconds(passwdInfo))
  return nextFileInfo
}

export async function cacheExternalWinZipAesZipNegative(fileInfo, error) {
  await levelDB.setExpire(
    probeKey(fileInfo.path),
    {
      path: normalizePath(fileInfo.path),
      size: normalizeSize(fileInfo.size),
      notPlayable: true,
      error: error && error.message ? error.message : String(error || ''),
      updatedAt: Date.now(),
    },
    NEGATIVE_CACHE_SECONDS
  )
}

async function processQueue() {
  if (probing) return
  probing = true
  try {
    while (probeQueue.length > 0) {
      const job = probeQueue.shift()
      const key = normalizePath(job.fileInfo.path)
      try {
        const cached = await getWinZipAesZipProbeCache(job.fileInfo.path, job.fileInfo.size, {
          ignoreInfoCache: !isZipInfoCacheEnabled(job.passwdInfo),
        })
        if (cached.type === 'miss') {
          const zipInfo = await parseWinZipAesZipInfoFromRemote(job.urlAddr, job.headers, job.fileInfo.size)
          await cacheExternalWinZipAesZipInfo(job.fileInfo, zipInfo, job.passwdInfo)
        }
      } catch (e) {
        await cacheExternalWinZipAesZipNegative(job.fileInfo, e)
      } finally {
        pendingKeys.delete(key)
      }
    }
  } finally {
    probing = false
  }
}

export function enqueueExternalWinZipAesZipProbe({ fileInfo, urlAddr, headers, passwdInfo }) {
  if (!fileInfo || fileInfo.is_dir || !String(fileInfo.name || '').toLowerCase().endsWith('.zip')) {
    return false
  }
  const key = normalizePath(fileInfo.path)
  if (!key || pendingKeys.has(key)) {
    return false
  }
  pendingKeys.add(key)
  probeQueue.push({
    fileInfo: {
      ...fileInfo,
      path: normalizePath(fileInfo.path),
      size: normalizeSize(fileInfo.size),
    },
    urlAddr,
    headers: { ...(headers || {}) },
    passwdInfo,
  })
  setTimeout(processQueue, 0)
  return true
}
