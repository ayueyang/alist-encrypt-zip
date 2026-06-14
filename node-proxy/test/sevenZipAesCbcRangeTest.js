import assert from 'assert'
import childProcess from 'child_process'
import fs from 'fs'
import http from 'http'
import os from 'os'
import path from 'path'
import { pipeline } from 'stream/promises'
import FlowEnc from '../src/utils/flowEnc'
import SevenZipAesCbc, {
  applySevenZipAesCbcResponseHeaders,
  decryptSevenZipAesCbcRange,
  deserializeSevenZipAesCbcInfo,
  getSevenZipAesCbcPackageName,
  isSevenZipAesCbcEncType,
  parseSevenZipAesCbcInfoFromFile,
  parseSevenZipAesCbcInfoFromRemote,
  prepareSevenZipAesCbcDownloadRequest,
  serializeSevenZipAesCbcInfo,
  SEVEN_ZIP_AES_CBC_DISPLAY_NAME,
  SEVEN_ZIP_AES_CBC_ENC_TYPE,
} from '../src/utils/sevenZipAesCbc'
import { fileInfoTable, getFileInfo, getZipInfoCacheExpireSeconds } from '../src/dao/fileDao'
import { httpProxy } from '../src/utils/httpClient'
import levelDB from '../src/utils/levelDB'
import {
  cacheExternalSevenZipAesCbcInfo,
  cacheGeneratedSevenZipAesCbcInfo,
  getSevenZipAesCbcPasswordHash,
  getSevenZipAesCbcUploadCachePaths,
  isSevenZipAesCbcFileName,
  isUsableSevenZipAesCbcInfoCache,
} from '../src/utils/sevenZipAesCbcCache'
import { getAListFileTypeByName } from '../src/utils/commonUtil'

const password = 'admin123'

function getSevenZipExe() {
  const candidates = ['C:\\Program Files\\7-Zip\\7z.exe', 'C:\\Program Files (x86)\\7-Zip\\7z.exe']
  const found = candidates.find((item) => fs.existsSync(item))
  if (!found) throw new Error('7z.exe not found')
  return found
}

function readFileRange(filePath, start, end) {
  const fd = fs.openSync(filePath, 'r')
  try {
    const length = end - start + 1
    const buffer = Buffer.alloc(length)
    const bytesRead = fs.readSync(fd, buffer, 0, length, start)
    return buffer.subarray(0, bytesRead)
  } finally {
    fs.closeSync(fd)
  }
}

function createSevenZipSample(plain, headerEncryption) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-7z-aes-cbc-'))
  const plainPath = path.join(tempDir, 'video.mp4')
  const archivePath = path.join(tempDir, headerEncryption ? 'hk-mhe.7z' : 'hk-no-mhe.7z')
  fs.writeFileSync(plainPath, plain)
  childProcess.execFileSync(getSevenZipExe(), [
    'a',
    '-t7z',
    '-mx=0',
    `-p${password}`,
    headerEncryption ? '-mhe=on' : '-mhe=off',
    archivePath,
    plainPath,
  ])
  return { tempDir, plainPath, archivePath }
}

function assertGeneratedArchiveHidesInternalName(archivePath) {
  const archiveBytes = fs.readFileSync(archivePath)
  assert.strictEqual(archiveBytes.includes(Buffer.from('video.mp4', 'utf16le')), false)
  assert.strictEqual(archiveBytes.includes(Buffer.from('video.mp4')), false)

  const hasInnerNameListEntry = (output) =>
    String(output || '')
      .split(/\r?\n/)
      .some((line) => {
        const text = line.trim()
        return text === 'video.mp4' || text.endsWith(' video.mp4') || text === 'Path = video.mp4'
      })

  const noPasswordList = childProcess.spawnSync(getSevenZipExe(), ['l', archivePath], {
    input: '\n',
    encoding: 'utf8',
    timeout: 10000,
  })
  const noPasswordOutput = `${noPasswordList.stdout || ''}${noPasswordList.stderr || ''}`
  assert.strictEqual(hasInnerNameListEntry(noPasswordOutput), false)

  const passwordList = childProcess.execFileSync(getSevenZipExe(), ['l', `-p${password}`, archivePath], {
    encoding: 'utf8',
  })
  assert.ok(hasInnerNameListEntry(passwordList))
}

async function decryptRange(archivePath, rangeHeader) {
  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromFile(archivePath, password)
  const request = { method: 'GET', headers: {}, url: '/video.mp4', sevenZipAesCbcVirtualName: 'video.mp4' }
  prepareSevenZipAesCbcDownloadRequest(request, sevenZipAesCbcInfo, rangeHeader)
  const encrypted = readFileRange(
    archivePath,
    request.sevenZipAesCbcPackageRange.start,
    request.sevenZipAesCbcPackageRange.end
  )
  return decryptSevenZipAesCbcRange(
    encrypted,
    sevenZipAesCbcInfo,
    request.sevenZipAesCbcPlainRange.start,
    request.sevenZipAesCbcPlainRange.end,
    password
  )
}

async function decryptRangeViaSevenZipAesCbcTransform(archivePath, rangeHeader) {
  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromFile(archivePath, password)
  const request = { method: 'GET', headers: {}, url: '/video.mp4', sevenZipAesCbcVirtualName: 'video.mp4' }
  const plainRange = prepareSevenZipAesCbcDownloadRequest(request, sevenZipAesCbcInfo, rangeHeader)
  const encrypted = readFileRange(
    archivePath,
    request.sevenZipAesCbcPackageRange.start,
    request.sevenZipAesCbcPackageRange.end
  )
  const sevenZipAesCbc = new SevenZipAesCbc(password, sevenZipAesCbcInfo.plainSize, {
    sevenZipAesCbcInfo,
    plainRange,
  })
  const chunks = []
  await pipeline(
    async function* () {
      for (let i = 0; i < encrypted.length; i += 17) {
        yield encrypted.subarray(i, i + 17)
      }
    },
    sevenZipAesCbc.decryptTransform(),
    async function* (source) {
      for await (const chunk of source) {
        chunks.push(chunk)
      }
    }
  )
  return Buffer.concat(chunks)
}

function createRangeServer(filePath, options = {}) {
  const server = http.createServer((req, res) => {
    const stat = fs.statSync(filePath)
    const range = req.headers.range
    if (req.method === 'HEAD') {
      res.setHeader('content-length', String(stat.size))
      res.end()
      return
    }
    if (range && !options.ignoreRange) {
      const [startText, endText] = String(range).replace('bytes=', '').split('-')
      const start = Number(startText || 0)
      const end = endText ? Number(endText) : stat.size - 1
      res.statusCode = 206
      res.setHeader('content-range', `bytes ${start}-${end}/${stat.size}`)
      res.setHeader('content-length', String(end - start + 1))
      fs.createReadStream(filePath, { start, end }).pipe(res)
      return
    }
    res.setHeader('content-length', String(stat.size))
    fs.createReadStream(filePath).pipe(res)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, url: `http://127.0.0.1:${address.port}/archive.7z` })
    })
  })
}

function requestText(urlAddr, options = {}, body = '') {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(urlAddr)
    const req = http.request(
      urlObj,
      {
        method: options.method || 'GET',
        headers: options.headers || {},
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          })
        })
      }
    )
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

function requestBuffer(urlAddr, options = {}, body = '') {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(urlAddr)
    const req = http.request(
      urlObj,
      {
        method: options.method || 'GET',
        headers: options.headers || {},
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks),
          })
        })
      }
    )
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

function createSevenZipWebdavOrigin(archivePath, webdavPath) {
  const server = http.createServer((req, res) => {
    const stat = fs.statSync(archivePath)
    if (req.method === 'PROPFIND') {
      res.statusCode = 207
      res.setHeader('content-type', 'application/xml; charset=utf-8')
      res.end(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>${webdavPath}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${path.basename(webdavPath)}</D:displayname>
        <D:getcontentlength>${stat.size}</D:getcontentlength>
      </D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>`)
      return
    }
    if (req.method === 'HEAD') {
      res.setHeader('content-length', String(stat.size))
      res.end()
      return
    }
    const range = req.headers.range
    if (range) {
      const [startText, endText] = String(range).replace('bytes=', '').split('-')
      const start = Number(startText || 0)
      const end = endText ? Number(endText) : stat.size - 1
      res.statusCode = 206
      res.setHeader('content-range', `bytes ${start}-${end}/${stat.size}`)
      res.setHeader('content-length', String(end - start + 1))
      fs.createReadStream(archivePath, { start, end }).pipe(res)
      return
    }
    res.setHeader('content-length', String(stat.size))
    fs.createReadStream(archivePath).pipe(res)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, serverAddr: `http://127.0.0.1:${address.port}` })
    })
  })
}

function createPlainOrigin(body) {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/plain; charset=utf-8')
    res.setHeader('content-disposition', 'attachment; filename="remote.txt";')
    res.setHeader('content-length', String(body.length))
    if (req.method === 'HEAD') {
      res.end()
      return
    }
    res.end(body)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, serverAddr: `http://127.0.0.1:${address.port}` })
    })
  })
}

function createWritableUploadOrigin() {
  const uploads = []
  const requests = []
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split('?')[0])
    requests.push({ method: req.method, url: urlPath, range: req.headers.range })
    if (req.method === 'PUT') {
      const chunks = []
      req.on('data', (chunk) => chunks.push(chunk))
      req.on('end', () => {
        uploads.push({
          url: urlPath,
          filePath: req.headers['file-path'] ? decodeURIComponent(req.headers['file-path']) : undefined,
          headers: { ...req.headers },
          body: Buffer.concat(chunks),
        })
        res.statusCode = 200
        res.end('ok')
      })
      return
    }

    if (req.method === 'PROPFIND' && urlPath.endsWith('/')) {
      const matchedUploads = uploads.filter((item) => path.dirname(item.url) + '/' === urlPath)
      res.statusCode = 207
      res.setHeader('content-type', 'application/xml; charset=utf-8')
      res.end(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
${matchedUploads
  .map(
    (item) => `  <D:response>
    <D:href>${item.url}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${path.basename(item.url)}</D:displayname>
        <D:getcontentlength>${item.body.length}</D:getcontentlength>
      </D:prop>
    </D:propstat>
  </D:response>`
  )
  .join('\n')}
</D:multistatus>`)
      return
    }

    const upload = uploads.find((item) => item.url === urlPath || item.filePath === urlPath)
    if (!upload) {
      res.statusCode = 404
      res.end('not found')
      return
    }
    if (req.method === 'PROPFIND') {
      res.statusCode = 207
      res.setHeader('content-type', 'application/xml; charset=utf-8')
      res.end(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>${upload.url}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${path.basename(upload.url)}</D:displayname>
        <D:getcontentlength>${upload.body.length}</D:getcontentlength>
      </D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>`)
      return
    }
    if (req.method === 'HEAD') {
      res.setHeader('content-length', String(upload.body.length))
      res.end()
      return
    }
    const range = req.headers.range
    if (range) {
      const [startText, endText] = String(range).replace('bytes=', '').split('-')
      const start = Number(startText || 0)
      const end = endText ? Number(endText) : upload.body.length - 1
      res.statusCode = 206
      res.setHeader('content-range', `bytes ${start}-${end}/${upload.body.length}`)
      res.setHeader('content-length', String(end - start + 1))
      res.end(upload.body.subarray(start, end + 1))
      return
    }
    res.setHeader('content-length', String(upload.body.length))
    res.end(upload.body)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, serverAddr: `http://127.0.0.1:${address.port}`, uploads, requests })
    })
  })
}

async function handleSevenZipWebdavDownload(ctx) {
  const request = ctx.req
  const passwdInfo = request.webdavConfig.passwdList[0]
  const fileInfo = await getFileInfo(request.url)
  const packageSize = Number((fileInfo && fileInfo.size) || 0)
  const cachedSevenZipAesCbcInfo = isUsableSevenZipAesCbcInfoCache(fileInfo, packageSize, passwdInfo.password)
    ? deserializeSevenZipAesCbcInfo(fileInfo.sevenZipAesCbcInfo)
    : null
  const sevenZipAesCbcInfo =
    cachedSevenZipAesCbcInfo ||
    (await parseSevenZipAesCbcInfoFromRemote(request.urlAddr, request.headers, packageSize, passwdInfo.password))
  const plainRange = prepareSevenZipAesCbcDownloadRequest(request, sevenZipAesCbcInfo, request.headers.range)
  request.passwdInfo = passwdInfo
  request.fileSize = packageSize || sevenZipAesCbcInfo.totalSize
  request.sevenZipAesCbcVirtualName = request.sevenZipAesCbcVirtualName || sevenZipAesCbcInfo.innerName
  request.followRemoteRedirect = true
  const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, sevenZipAesCbcInfo.plainSize, {
    sevenZipAesCbcInfo,
    plainRange,
  })
  await flowEnc.setPosition(plainRange.start || 0)
  if (request.method.toLocaleUpperCase() === 'HEAD') {
    ctx.res.statusCode = request.sevenZipAesCbcPlainRange.hasRange ? 206 : 200
    applySevenZipAesCbcResponseHeaders(ctx.res, request)
    ctx.res.end()
    return
  }
  await httpProxy(request, ctx.res, null, flowEnc.decryptTransform())
}

function listenKoa(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve({ server, url: `http://127.0.0.1:${address.port}` })
    })
  })
}

async function assertArchive(archivePath, plain) {
  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromFile(archivePath, password)
  assert.strictEqual(sevenZipAesCbcInfo.encType, SEVEN_ZIP_AES_CBC_ENC_TYPE)
  assert.strictEqual(sevenZipAesCbcInfo.innerName, 'video.mp4')
  assert.strictEqual(sevenZipAesCbcInfo.plainSize, plain.length)
  assert.strictEqual(sevenZipAesCbcInfo.method, 'copy+7zaes')
  assert.strictEqual(sevenZipAesCbcInfo.solid, false)
  assert.strictEqual(sevenZipAesCbcInfo.cycles, 19)
  assert.strictEqual(sevenZipAesCbcInfo.iv.length, 16)

  const serialized = serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo)
  const deserialized = deserializeSevenZipAesCbcInfo(serialized)
  assert.deepStrictEqual(deserialized.salt, sevenZipAesCbcInfo.salt)
  assert.deepStrictEqual(deserialized.iv, sevenZipAesCbcInfo.iv)

  const ranges = [
    [0, 31],
    [1, 37],
    [15, 80],
    [16, 95],
    [17, 96],
    [1048579, 1052675],
    [Math.floor(plain.length / 2) - 23, Math.floor(plain.length / 2) + 997],
    [plain.length - 1000, plain.length - 1],
  ]
  for (const [start, end] of ranges) {
    const actual = await decryptRange(archivePath, `bytes=${start}-${end}`)
    assert.deepStrictEqual(actual, plain.subarray(start, end + 1), `range ${start}-${end}`)
  }
  const suffix = await decryptRange(archivePath, 'bytes=-1024')
  assert.deepStrictEqual(suffix, plain.subarray(plain.length - 1024))
  const full = await decryptRange(archivePath)
  assert.deepStrictEqual(full, plain)

  const flowRange = await decryptRangeViaSevenZipAesCbcTransform(archivePath, 'bytes=17-96')
  assert.deepStrictEqual(flowRange, plain.subarray(17, 97))

  const headRequest = { method: 'HEAD', headers: {}, url: '/video.mp4', sevenZipAesCbcVirtualName: 'video.mp4' }
  prepareSevenZipAesCbcDownloadRequest(headRequest, sevenZipAesCbcInfo, 'bytes=1-37')
  const headers = {}
  const response = {
    statusCode: 200,
    setHeader(key, value) {
      headers[key.toLowerCase()] = value
    },
    removeHeader(key) {
      delete headers[key.toLowerCase()]
    },
  }
  applySevenZipAesCbcResponseHeaders(response, headRequest)
  assert.strictEqual(response.statusCode, 206)
  assert.strictEqual(headers['content-range'], `bytes 1-37/${plain.length}`)
  assert.strictEqual(headers['content-length'], '37')
  assert.strictEqual(headers['content-type'], 'video/mp4')
}

async function assertRemoteArchive(archivePath, plain) {
  const { server, url } = await createRangeServer(archivePath)
  try {
    const remoteInfo = await parseSevenZipAesCbcInfoFromRemote(url, {}, 0, password)
    assert.strictEqual(remoteInfo.plainSize, plain.length)
    assert.strictEqual(remoteInfo.innerName, 'video.mp4')
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }

  const fallback = await createRangeServer(archivePath, { ignoreRange: true })
  try {
    const remoteInfo = await parseSevenZipAesCbcInfoFromRemote(fallback.url, {}, 0, password)
    assert.strictEqual(remoteInfo.plainSize, plain.length)
    assert.strictEqual(remoteInfo.innerName, 'video.mp4')
  } finally {
    await new Promise((resolve) => fallback.server.close(resolve))
  }
}

async function assertAListEntryMiddleware(archivePath, plain) {
  process.env.RUN_MODE = 'DEV'
  // eslint-disable-next-line no-undef
  const Koa = require('koa')
  // eslint-disable-next-line no-undef
  const encNameRouter = require('../src/encNameRouter').default
  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromFile(archivePath, password)
  const stat = fs.statSync(archivePath)
  const alistPath = `/alist-${Date.now()}/movie.7z`
  await cacheExternalSevenZipAesCbcInfo(
    { path: alistPath, name: 'movie.7z', size: stat.size, is_dir: false },
    sevenZipAesCbcInfo,
    password
  )

  const app = new Koa()
  app.use(async (ctx, next) => {
    ctx.req.webdavConfig = {
      passwdList: [
        {
          enable: true,
          encName: true,
          encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
          encPath: ['^/alist-'],
          password,
          sevenZipAesCbcAutoCache: false,
        },
      ],
    }
    await next()
  })
  app.use(encNameRouter.routes()).use(encNameRouter.allowedMethods())
  app.use(async (ctx) => {
    ctx.body = {
      code: 200,
      data: {
        name: path.basename(ctx.request.body.path),
        type: getAListFileTypeByName(ctx.request.body.path),
        raw_path: ctx.request.body.path,
      },
    }
  })

  const { server, url } = await listenKoa(app)
  try {
    const resp = await requestText(
      `${url}/api/fs/get`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      },
      JSON.stringify({ path: alistPath })
    )
    const result = JSON.parse(resp.body)
    assert.strictEqual(result.data.name, 'video.mp4')
    assert.strictEqual(result.data.raw_path, alistPath)
    assert.strictEqual(result.data.type, getAListFileTypeByName(sevenZipAesCbcInfo.innerName))

    const virtualResp = await requestText(
      `${url}/api/fs/get`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      },
      JSON.stringify({ path: `${path.dirname(alistPath)}/video.mp4` })
    )
    const virtualResult = JSON.parse(virtualResp.body)
    assert.strictEqual(virtualResult.data.name, 'video.mp4')
    assert.strictEqual(virtualResult.data.raw_path, alistPath)
    assert.strictEqual(virtualResult.data.type, getAListFileTypeByName('video.mp4'))

    const plainResp = await requestText(
      `${url}/api/fs/get`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      },
      JSON.stringify({ path: `${path.dirname(alistPath)}/plain.txt` })
    )
    const plainResult = JSON.parse(plainResp.body)
    assert.strictEqual(plainResult.data.name, 'plain.txt')
    assert.strictEqual(plainResult.data.raw_path, `${path.dirname(alistPath)}/plain.txt`)
    assert.strictEqual(plainResult.data.type, getAListFileTypeByName('plain.txt'))
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
}

async function assertWebdavPropfindMiddleware(archivePath, plain) {
  process.env.RUN_MODE = 'DEV'
  // eslint-disable-next-line no-undef
  const Koa = require('koa')
  // eslint-disable-next-line no-undef
  const encDavHandle = require('../src/encDavHandle').default
  const webdavPath = `/dav-${Date.now()}/movie.7z`
  const { server: originServer, serverAddr } = await createSevenZipWebdavOrigin(archivePath, webdavPath)
  const app = new Koa()
  app.use(async (ctx, next) => {
    ctx.req.webdavConfig = {
      passwdList: [
        {
          enable: true,
          encName: true,
          encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
          encPath: ['^/dav-'],
          password,
          sevenZipAesCbcAutoCache: false,
        },
      ],
    }
    ctx.req.serverAddr = serverAddr
    ctx.req.urlAddr = serverAddr + ctx.req.url
    await next()
  })
  app.use(encDavHandle)
  app.use(handleSevenZipWebdavDownload)

  const { server, url } = await listenKoa(app)
  try {
    const resp = await requestText(`${url}${path.dirname(webdavPath)}/`, { method: 'PROPFIND' })
    assert.strictEqual(resp.statusCode, 207)
    assert.ok(resp.body.includes(`<D:getcontentlength>${plain.length}</D:getcontentlength>`))
    assert.ok(resp.body.includes('<D:displayname>video.mp4</D:displayname>'))
    assert.ok(!resp.body.includes(`<D:displayname>${path.basename(webdavPath)}</D:displayname>`))
    assert.ok(!resp.body.includes('orig_'))

    const fullHeadResp = await requestBuffer(`${url}${webdavPath}`, { method: 'HEAD' })
    assert.strictEqual(fullHeadResp.statusCode, 200)
    assert.strictEqual(fullHeadResp.headers['content-length'], String(plain.length))
    assert.strictEqual(fullHeadResp.headers['content-type'], 'video/mp4')
    assert.strictEqual(fullHeadResp.body.length, 0)

    const headResp = await requestBuffer(`${url}${webdavPath}`, {
      method: 'HEAD',
      headers: { Range: 'bytes=1-37' },
    })
    assert.strictEqual(headResp.statusCode, 206)
    assert.strictEqual(headResp.headers['content-range'], `bytes 1-37/${plain.length}`)
    assert.strictEqual(headResp.headers['content-length'], '37')
    assert.strictEqual(headResp.headers['content-type'], 'video/mp4')
    assert.strictEqual(headResp.body.length, 0)

    const getResp = await requestBuffer(`${url}${webdavPath}`, {
      method: 'GET',
      headers: { Range: 'bytes=17-96' },
    })
    assert.strictEqual(getResp.statusCode, 206)
    assert.strictEqual(getResp.headers['content-range'], `bytes 17-96/${plain.length}`)
    assert.strictEqual(getResp.headers['content-length'], '80')
    assert.strictEqual(getResp.headers['content-type'], 'video/mp4')
    assert.deepStrictEqual(getResp.body, plain.subarray(17, 97))
  } finally {
    await new Promise((resolve) => server.close(resolve))
    await new Promise((resolve) => originServer.close(resolve))
  }
}

async function assertSevenZipPlainPassthroughFileName() {
  process.env.RUN_MODE = 'DEV'
  // eslint-disable-next-line no-undef
  const Koa = require('koa')
  const body = Buffer.from('plain passthrough')
  const { server: originServer, serverAddr } = await createPlainOrigin(body)
  const app = new Koa()
  app.use(async (ctx) => {
    ctx.req.urlAddr = serverAddr + ctx.req.url
    ctx.req.passwdInfo = {
      enable: true,
      encName: true,
      encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
      password,
    }
    await httpProxy(ctx.req, ctx.res)
  })

  const { server, url } = await listenKoa(app)
  try {
    const getResp = await requestBuffer(`${url}/plain.txt`, { method: 'GET' })
    assert.strictEqual(getResp.statusCode, 200)
    assert.deepStrictEqual(getResp.body, body)
    assert.ok(String(getResp.headers['content-disposition']).includes(`filename*=UTF-8''plain.txt;`))
    assert.ok(!String(getResp.headers['content-disposition']).includes('orig_'))

    const headResp = await requestBuffer(`${url}/plain.txt`, { method: 'HEAD' })
    assert.strictEqual(headResp.statusCode, 200)
    assert.strictEqual(headResp.headers['content-length'], String(body.length))
    assert.strictEqual(headResp.body.length, 0)
  } finally {
    await new Promise((resolve) => server.close(resolve))
    await new Promise((resolve) => originServer.close(resolve))
  }
}

async function assertGeneratedUploadArchive(upload, plain, expectedPath) {
  assert.ok(upload, 'upload should reach origin')
  assert.strictEqual(upload.filePath || upload.url, expectedPath)
  assert.strictEqual(Number(upload.headers['content-length']), SevenZipAesCbc.packageSize(plain.length, { originalName: 'video.mp4' }))
  assert.strictEqual(upload.body.length, SevenZipAesCbc.packageSize(plain.length, { originalName: 'video.mp4' }))

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-7z-aes-cbc-upload-'))
  const archivePath = path.join(tempDir, path.basename(expectedPath))
  fs.writeFileSync(archivePath, upload.body)

  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromFile(archivePath, password)
  assert.strictEqual(sevenZipAesCbcInfo.innerName, 'video.mp4')
  assert.strictEqual(sevenZipAesCbcInfo.plainSize, plain.length)
  assert.strictEqual(sevenZipAesCbcInfo.packedSize % 16, 0)

  const full = await decryptRange(archivePath)
  assert.deepStrictEqual(full, plain)
  const range = await decryptRange(archivePath, 'bytes=1-37')
  assert.deepStrictEqual(range, plain.subarray(1, 38))
  childProcess.execFileSync(getSevenZipExe(), ['t', `-p${password}`, archivePath])
  assertGeneratedArchiveHidesInternalName(archivePath)
}

async function getRawCacheRecord(filePath) {
  return await levelDB.datastore.findOne({ key: fileInfoTable + decodeURIComponent(filePath) })
}

async function assertGeneratedUploadCache(expectedPath, plain) {
  const cachedFileInfo = await getFileInfo(expectedPath)
  assert.ok(cachedFileInfo, `cache not found for ${expectedPath}`)
  assert.strictEqual(cachedFileInfo.name, path.basename(expectedPath))
  assert.strictEqual(cachedFileInfo.size, SevenZipAesCbc.packageSize(plain.length, { originalName: 'video.mp4' }))
  assert.strictEqual(cachedFileInfo.plainSize, plain.length)
  assert.strictEqual(cachedFileInfo.externalSevenZipAesCbc, true)
  assert.strictEqual(cachedFileInfo.sevenZipAesCbcVirtualName, 'video.mp4')
  assert.strictEqual(cachedFileInfo.sevenZipAesCbcPasswordHash, getSevenZipAesCbcPasswordHash(password))
  assert.ok(isUsableSevenZipAesCbcInfoCache(cachedFileInfo, cachedFileInfo.size, password))
  const cachedSevenZipAesCbcInfo = deserializeSevenZipAesCbcInfo(cachedFileInfo.sevenZipAesCbcInfo)
  assert.strictEqual(cachedSevenZipAesCbcInfo.innerName, 'video.mp4')
  assert.strictEqual(cachedSevenZipAesCbcInfo.plainSize, plain.length)
}

async function assertZipInfoCachePolicy() {
  assert.strictEqual(getZipInfoCacheExpireSeconds({}), 30 * 24 * 60 * 60)
  assert.strictEqual(getZipInfoCacheExpireSeconds({ zipInfoCacheDays: 2 }), 2 * 24 * 60 * 60)

  const cacheOffPath = `/zip-info-cache-off-${Date.now()}.7z`
  const cacheOffResult = await cacheGeneratedSevenZipAesCbcInfo({
    password,
    passwdInfo: { password, zipInfoCache: false, zipInfoCacheDays: 2 },
    filePath: cacheOffPath,
    realName: path.basename(cacheOffPath),
    originalName: 'video.mp4',
    plainSize: 123,
    packageSize: SevenZipAesCbc.packageSize(123, { originalName: 'video.mp4' }),
    iv: Buffer.alloc(16),
  })
  assert.strictEqual(cacheOffResult, null)
  assert.strictEqual(await getFileInfo(cacheOffPath), null)

  const ttlPath = `/zip-info-cache-ttl-${Date.now()}.7z`
  await cacheGeneratedSevenZipAesCbcInfo({
    password,
    passwdInfo: { password, zipInfoCache: true, zipInfoCacheDays: 2 },
    filePath: ttlPath,
    realName: path.basename(ttlPath),
    originalName: 'video.mp4',
    plainSize: 123,
    packageSize: SevenZipAesCbc.packageSize(123, { originalName: 'video.mp4' }),
    iv: Buffer.alloc(16),
  })
  const rawCacheRecord = await getRawCacheRecord(ttlPath)
  assert.ok(rawCacheRecord && rawCacheRecord.expire > Date.now())
  const ttlSeconds = Math.round((rawCacheRecord.expire - Date.now()) / 1000)
  assert.ok(Math.abs(ttlSeconds - 2 * 24 * 60 * 60) < 10, `unexpected zipInfoCache TTL: ${ttlSeconds}`)
}

async function assertAListUploadPackagesSevenZipAesCbc(plain) {
  process.env.RUN_MODE = 'DEV'
  // eslint-disable-next-line no-undef
  const Koa = require('koa')
  // eslint-disable-next-line no-undef
  const encNameRouter = require('../src/encNameRouter').default
  const { server: originServer, serverAddr, uploads } = await createWritableUploadOrigin()
  const app = new Koa()
  app.use(async (ctx, next) => {
    ctx.req.webdavConfig = {
      passwdList: [
        {
          enable: true,
          encName: true,
          encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
          encPath: ['^/alist-upload-'],
          password,
        },
      ],
    }
    ctx.req.serverAddr = serverAddr
    ctx.req.urlAddr = serverAddr + ctx.req.url
    await next()
  })
  app.use(encNameRouter.routes()).use(encNameRouter.allowedMethods())

  const { server, url } = await listenKoa(app)
  try {
    const uploadPath = '/alist-upload-dir/video.mp4'
    const resp = await requestBuffer(
      `${url}/api/fs/put`,
      {
        method: 'PUT',
        headers: {
          'file-path': encodeURIComponent(uploadPath),
          'content-length': String(plain.length),
        },
      },
      plain
    )
    assert.strictEqual(resp.statusCode, 200)
    assert.strictEqual(uploads.length, 1)
    await assertGeneratedUploadArchive(uploads[0], plain, '/alist-upload-dir/video.mp4.7z')
    await assertGeneratedUploadCache('/alist-upload-dir/video.mp4.7z', plain)
    await assertGeneratedUploadCache('/dav/alist-upload-dir/video.mp4.7z', plain)
  } finally {
    await new Promise((resolve) => server.close(resolve))
    await new Promise((resolve) => originServer.close(resolve))
  }
}

async function assertWebdavUploadPackagesSevenZipAesCbc(plain) {
  process.env.RUN_MODE = 'DEV'
  // eslint-disable-next-line no-undef
  const Koa = require('koa')
  // eslint-disable-next-line no-undef
  const encDavHandle = require('../src/encDavHandle').default
  const { server: originServer, serverAddr, uploads, requests } = await createWritableUploadOrigin()
  const app = new Koa()
  app.use(async (ctx, next) => {
    ctx.req.webdavConfig = {
      passwdList: [
        {
          enable: true,
          encName: true,
          encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
          encPath: ['^/dav/dav-upload-'],
          password,
        },
      ],
    }
    ctx.req.serverAddr = serverAddr
    ctx.req.urlAddr = serverAddr + ctx.req.url
    ctx.req.isWebdav = true
    await next()
  })
  app.use(encDavHandle)
  app.use(async (ctx) => {
    const request = ctx.req
    const passwdInfo = request.webdavConfig.passwdList[0]
    if (request.method.toLocaleUpperCase() !== 'PUT') {
      await handleSevenZipWebdavDownload(ctx)
      return
    }
    const contentLength = request.headers['content-length'] || request.headers['x-expected-entity-length'] || 0
    request.fileSize = Number(contentLength) || 0
    request.passwdInfo = passwdInfo
    request.headers['content-length'] = String(SevenZipAesCbc.packageSize(request.fileSize, { originalName: request.originalName }))
    delete request.headers['x-expected-entity-length']
    const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, request.fileSize, {
      originalName: request.originalName,
    })
    if (isSevenZipAesCbcEncType(passwdInfo.encType)) {
      for (const cachePath of getSevenZipAesCbcUploadCachePaths(request.url)) {
        await cacheGeneratedSevenZipAesCbcInfo({
          password: passwdInfo.password,
          passwdInfo,
          filePath: cachePath,
          realName: path.basename(cachePath),
          originalName: request.originalName,
          plainSize: request.fileSize,
          packageSize: Number(request.headers['content-length']),
          iv: flowEnc.encryptFlow.iv,
        })
      }
    }
    await httpProxy(request, ctx.res, flowEnc.encryptTransform())
  })

  const { server, url } = await listenKoa(app)
  try {
    const uploadPath = '/dav/dav-upload-dir/video.mp4'
    const resp = await requestBuffer(
      `${url}${uploadPath}`,
      {
        method: 'PUT',
        headers: {
          'content-length': String(plain.length),
        },
      },
      plain
    )
    assert.strictEqual(resp.statusCode, 200)
    assert.strictEqual(uploads.length, 1)
    await assertGeneratedUploadArchive(uploads[0], plain, '/dav/dav-upload-dir/video.mp4.7z')
    await assertGeneratedUploadCache('/dav/dav-upload-dir/video.mp4.7z', plain)
    await assertGeneratedUploadCache('/dav-upload-dir/video.mp4.7z', plain)

    const propfindResp = await requestText(`${url}${path.dirname(uploadPath)}/`, { method: 'PROPFIND' })
    assert.strictEqual(propfindResp.statusCode, 207)
    assert.ok(propfindResp.body.includes('<D:displayname>video.mp4</D:displayname>'))
    assert.ok(!propfindResp.body.includes('<D:displayname>video.mp4.7z</D:displayname>'))

    const fullHeadResp = await requestBuffer(`${url}${uploadPath}`, { method: 'HEAD' })
    assert.strictEqual(fullHeadResp.statusCode, 200)
    assert.strictEqual(fullHeadResp.headers['content-length'], String(plain.length))
    assert.strictEqual(fullHeadResp.headers['content-type'], 'video/mp4')

    const headResp = await requestBuffer(`${url}${uploadPath}`, {
      method: 'HEAD',
      headers: { Range: 'bytes=1-37' },
    })
    assert.strictEqual(headResp.statusCode, 206)
    assert.strictEqual(headResp.headers['content-range'], `bytes 1-37/${plain.length}`)
    assert.strictEqual(headResp.headers['content-length'], '37')
    assert.strictEqual(headResp.headers['content-type'], 'video/mp4')

    const getResp = await requestBuffer(`${url}${uploadPath}`, {
      method: 'GET',
      headers: { Range: 'bytes=17-96' },
    })
    assert.strictEqual(getResp.statusCode, 206)
    assert.strictEqual(getResp.headers['content-range'], `bytes 17-96/${plain.length}`)
    assert.strictEqual(getResp.headers['content-length'], '80')
    assert.strictEqual(getResp.headers['content-type'], 'video/mp4')
    assert.deepStrictEqual(getResp.body, plain.subarray(17, 97))
    assert.ok(
      requests.some((item) => item.method === 'GET' && item.url === '/dav/dav-upload-dir/video.mp4.7z'),
      'webdav virtual download should request the 7z AES-CBC package path'
    )
  } finally {
    await new Promise((resolve) => server.close(resolve))
    await new Promise((resolve) => originServer.close(resolve))
  }
}

async function main() {
  assert.strictEqual(SEVEN_ZIP_AES_CBC_ENC_TYPE, '7z-aes-cbc')
  assert.strictEqual(SEVEN_ZIP_AES_CBC_DISPLAY_NAME, '7z AES-CBC')
  assert.ok(isSevenZipAesCbcEncType(SEVEN_ZIP_AES_CBC_ENC_TYPE))
  assert.ok(!isSevenZipAesCbcEncType('winzip-aes-ctr'))
  assert.ok(isSevenZipAesCbcFileName('movie.7z'))
  assert.ok(!isSevenZipAesCbcFileName('movie.zip'))
  assert.strictEqual(getSevenZipAesCbcPackageName('movie.mp4'), 'movie.mp4.7z')
  assert.strictEqual(getSevenZipAesCbcPackageName('movie.7z'), 'movie.7z')
  assert.strictEqual(deserializeSevenZipAesCbcInfo({ encType: 'winzip-aes-ctr' }), null)

  const plain = Buffer.concat([
    Buffer.from('ftypisom'),
    Buffer.alloc(32, 0),
    Buffer.from('mp4-head'),
    Buffer.alloc(2 * 1024 * 1024 + 337, 0x5a),
    Buffer.from('7z aes cbc tail'),
  ])

  let webdavArchivePath = null
  for (const headerEncryption of [false, true]) {
    const { archivePath } = createSevenZipSample(plain, headerEncryption)
    await assertArchive(archivePath, plain)
    await assertRemoteArchive(archivePath, plain)
    if (headerEncryption) webdavArchivePath = archivePath
  }

  const cacheInfo = await cacheExternalSevenZipAesCbcInfo(
    { path: '/dav/movie.7z', name: 'movie.7z', size: 123, is_dir: false },
    {
      encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
      plainSize: plain.length,
      innerName: 'video.mp4',
      salt: Buffer.alloc(0),
      iv: Buffer.alloc(16),
    },
    password
  )
  assert.strictEqual(cacheInfo.sevenZipAesCbcPasswordHash, getSevenZipAesCbcPasswordHash(password))
  assert.ok(isUsableSevenZipAesCbcInfoCache(cacheInfo, 123, password))
  assert.ok(!isUsableSevenZipAesCbcInfoCache(cacheInfo, 123, 'wrong-password'))
  assert.strictEqual(cacheInfo.externalSevenZipAesCbc, true)

  await assertAListEntryMiddleware(webdavArchivePath, plain)
  await assertWebdavPropfindMiddleware(webdavArchivePath, plain)
  await assertSevenZipPlainPassthroughFileName()
  await assertZipInfoCachePolicy()
  await assertAListUploadPackagesSevenZipAesCbc(plain.subarray(0, 65591))
  await assertWebdavUploadPackagesSevenZipAesCbc(plain.subarray(0, 65591))

  console.log('sevenZipAesCbcRangeTest ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
