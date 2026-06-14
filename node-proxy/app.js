'use strict'
import { convertFile } from '@/utils/convertFile'
const arg = process.argv.slice(2)
if (arg.length > 1) {
  // convertFile command
  convertFile(...arg)
  return
}

import Koa from 'koa'
import Router from 'koa-router'
import http from 'http'
import crypto from 'crypto'
import path from 'path'
import { httpProxy, httpClient } from '@/utils/httpClient'
import bodyparser from 'koa-bodyparser'
import FlowEnc from '@/utils/flowEnc'
import WinZipAesZip, {
  deserializeWinZipAesZipInfo,
  getMimeByName,
  isWinZipAesEncType,
  parseManagedWinZipAesZipInfoFromRemote,
  parseWinZipAesZipInfoFromRemote,
  prepareWinZipAesDownloadRequest,
  serializeWinZipAesZipInfo,
} from '@/utils/winZipAesZip'
import SevenZipAesCbc, {
  applySevenZipAesCbcResponseHeaders,
  deserializeSevenZipAesCbcInfo,
  getSevenZipAesCbcPackageName,
  isSevenZipAesCbcEncType,
  parseSevenZipAesCbcInfoFromRemote,
  prepareSevenZipAesCbcDownloadRequest,
  serializeSevenZipAesCbcInfo,
} from '@/utils/sevenZipAesCbc'
import levelDB from '@/utils/levelDB'
import { webdavServer, alistServer, port, version } from '@/config'
import { convertRealName, getAListFileTypeByName, isRawZipName, pathExec, pathFindPasswd } from '@/utils/commonUtil'
import globalHandle from '@/middleware/globalHandle'
import encApiRouter from '@/router'
import encNameRouter from '@/encNameRouter'
import encDavHandle from '@/encDavHandle'

import { cacheFileInfo, getFileInfo, getZipInfoCacheExpireSeconds, isZipInfoCacheEnabled } from '@/dao/fileDao'
import { getWebdavFileInfo } from '@/utils/webdavClient'
import staticServer from 'koa-static'
import { logger } from '@/common/logger'
import {
  cacheExternalWinZipAesZipInfo,
  cacheExternalWinZipAesZipNegative,
  cacheManagedWinZipAesZipInfo,
  getWinZipAesZipProbeCache,
  isUsableWinZipAesZipInfoCache,
} from '@/utils/winZipAesZipCache'
import {
  cacheExternalSevenZipAesCbcInfo,
  cacheExternalSevenZipAesCbcNegative,
  cacheGeneratedSevenZipAesCbcInfo,
  getSevenZipAesCbcUploadCachePaths,
  getSevenZipAesCbcPasswordHash,
  getSevenZipAesCbcProbeCache,
  isUsableSevenZipAesCbcInfoCache,
  isSevenZipAesCbcFileName,
} from '@/utils/sevenZipAesCbcCache'

async function sleep(time) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, time || 3000)
  })
}

function getRangeStart(range) {
  return range ? Number(String(range).replace('bytes=', '').split('-')[0] || 0) : 0
}

function setWinZipAesUploadSize(request, passwdInfo, plainSize, originalName) {
  if (!isWinZipAesEncType(passwdInfo.encType)) return
  const packageSize = WinZipAesZip.packageSize(plainSize, {
    originalName,
  })
  request.headers['content-length'] = String(packageSize)
  delete request.headers['x-expected-entity-length']
}

function setSevenZipAesCbcUploadSize(request, passwdInfo, plainSize, originalName) {
  if (!isSevenZipAesCbcEncType(passwdInfo.encType)) return null
  const packageSize = SevenZipAesCbc.packageSize(plainSize, {
    originalName,
  })
  request.headers['content-length'] = String(packageSize)
  delete request.headers['x-expected-entity-length']
  return packageSize
}

async function cacheGeneratedSevenZipAesCbcUploadInfo(passwdInfo, filePath, originalName, plainSize, packageSize, iv) {
  if (!isSevenZipAesCbcEncType(passwdInfo.encType)) return
  for (const cachePath of getSevenZipAesCbcUploadCachePaths(filePath)) {
    await cacheGeneratedSevenZipAesCbcInfo({
      password: passwdInfo.password,
      passwdInfo,
      filePath: cachePath,
      realName: path.basename(cachePath),
      originalName,
      plainSize,
      packageSize,
      iv,
    })
  }
}

async function prepareWinZipAesDecrypt(request, passwdInfo, zipSize, rangeHeader, cachedZipInfo = null) {
  const validCachedZipInfo =
    cachedZipInfo && Number(cachedZipInfo.totalSize) === Number(zipSize) ? cachedZipInfo : null
  const zipInfo =
    validCachedZipInfo ||
    (await parseWinZipAesZipInfoFromRemote(request.urlAddr, request.headers, zipSize))
  request.zipVirtualName =
    request.zipVirtualName ||
    (request.isExternalZip || request.isExternalZipCandidate
      ? zipInfo.innerName
      : path.basename(decodeURIComponent(request.url.split('?')[0] || zipInfo.innerName)))
  prepareWinZipAesDownloadRequest(request, zipInfo, rangeHeader)
  const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, zipInfo.plainSize, { zipInfo })
  await flowEnc.setPosition(request.zipCipherStart || 0)
  return flowEnc
}

async function prepareSevenZipAesCbcDecrypt(request, passwdInfo, packageSize, rangeHeader, cachedSevenZipAesCbcInfo = null) {
  const validCachedSevenZipAesCbcInfo =
    cachedSevenZipAesCbcInfo && Number(cachedSevenZipAesCbcInfo.totalSize) === Number(packageSize)
      ? cachedSevenZipAesCbcInfo
      : null
  const sevenZipAesCbcInfo =
    validCachedSevenZipAesCbcInfo ||
    (await parseSevenZipAesCbcInfoFromRemote(request.urlAddr, request.headers, packageSize, passwdInfo.password))
  request.sevenZipAesCbcVirtualName =
    request.sevenZipAesCbcVirtualName ||
    (request.isExternalSevenZipAesCbc || request.isExternalSevenZipAesCbcCandidate
      ? sevenZipAesCbcInfo.innerName
      : path.basename(decodeURIComponent(request.url.split('?')[0] || sevenZipAesCbcInfo.innerName)))
  const plainRange = prepareSevenZipAesCbcDownloadRequest(request, sevenZipAesCbcInfo, rangeHeader)
  const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, sevenZipAesCbcInfo.plainSize, {
    sevenZipAesCbcInfo,
    plainRange,
  })
  await flowEnc.setPosition(plainRange.start || 0)
  return flowEnc
}

async function prepareExternalWinZipAesZipInfo(request, fileInfo, parseUrl, headers, passwdInfo = {}, options = {}) {
  const enableZipInfoCache = isZipInfoCacheEnabled(passwdInfo)
  const probeCache = await getWinZipAesZipProbeCache(fileInfo.path, fileInfo.size, {
    ignoreInfoCache: !enableZipInfoCache,
  })
  if (probeCache.type === 'hit') {
    return probeCache.fileInfo
  }
  if (probeCache.type === 'negative') {
    return null
  }
  try {
    const zipInfo = await parseWinZipAesZipInfoFromRemote(parseUrl, headers, fileInfo.size, options)
    return await cacheExternalWinZipAesZipInfo(fileInfo, zipInfo, passwdInfo)
  } catch (e) {
    await cacheExternalWinZipAesZipNegative(fileInfo, e)
    return null
  }
}

async function prepareManagedWinZipAesZipInfo(request, passwdInfo, fileInfo, parseUrl, headers, options = {}) {
  const enableZipInfoCache = isZipInfoCacheEnabled(passwdInfo)
  if (enableZipInfoCache) {
    const cachedFileInfo = (await getFileInfo(fileInfo.path)) || (await getFileInfo(encodeURIComponent(fileInfo.path)))
    if (isUsableWinZipAesZipInfoCache(cachedFileInfo, fileInfo.size)) {
      return cachedFileInfo
    }
  }
  let zipInfo
  try {
    zipInfo = await parseManagedWinZipAesZipInfoFromRemote(parseUrl, headers, fileInfo.size, options)
  } catch (e) {
    zipInfo = await parseWinZipAesZipInfoFromRemote(parseUrl, headers, fileInfo.size, options)
  }
  const nextFileInfo = {
    ...fileInfo,
    plainSize: zipInfo.plainSize,
    zipInfo: serializeWinZipAesZipInfo(zipInfo),
  }
  if (!enableZipInfoCache) {
    return nextFileInfo
  }
  return await cacheManagedWinZipAesZipInfo(nextFileInfo, zipInfo, passwdInfo)
}

async function prepareExternalSevenZipAesCbcInfo(request, fileInfo, parseUrl, headers, passwdInfo, options = {}) {
  const enableZipInfoCache = isZipInfoCacheEnabled(passwdInfo)
  const probeCache = await getSevenZipAesCbcProbeCache(fileInfo.path, fileInfo.size, passwdInfo.password, {
    ignoreInfoCache: !enableZipInfoCache,
  })
  if (probeCache.type === 'hit') {
    return probeCache.fileInfo
  }
  if (probeCache.type === 'negative') {
    return null
  }
  try {
    const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromRemote(
      parseUrl,
      headers,
      fileInfo.size,
      passwdInfo.password,
      options
    )
    return await cacheExternalSevenZipAesCbcInfo(fileInfo, sevenZipAesCbcInfo, passwdInfo)
  } catch (e) {
    await cacheExternalSevenZipAesCbcNegative(fileInfo, e, passwdInfo.password)
    return null
  }
}

async function prepareManagedSevenZipAesCbcInfo(request, passwdInfo, fileInfo, parseUrl, headers, options = {}) {
  const enableZipInfoCache = isZipInfoCacheEnabled(passwdInfo)
  if (enableZipInfoCache) {
    const cachedFileInfo = (await getFileInfo(fileInfo.path)) || (await getFileInfo(encodeURIComponent(fileInfo.path)))
    if (isUsableSevenZipAesCbcInfoCache(cachedFileInfo, fileInfo.size, passwdInfo.password)) {
      return cachedFileInfo
    }
  }
  const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromRemote(
    parseUrl,
    headers,
    fileInfo.size,
    passwdInfo.password,
    options
  )
  const nextFileInfo = {
    ...fileInfo,
    plainSize: sevenZipAesCbcInfo.plainSize,
    sevenZipAesCbcInfo: serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo),
    externalSevenZipAesCbc: fileInfo.externalSevenZipAesCbc || false,
    sevenZipAesCbcPasswordHash: getSevenZipAesCbcPasswordHash(passwdInfo.password),
    sevenZipAesCbcVirtualName: fileInfo.sevenZipAesCbcVirtualName,
  }
  if (!enableZipInfoCache) {
    return nextFileInfo
  }
  return await cacheExternalSevenZipAesCbcInfo(nextFileInfo, sevenZipAesCbcInfo, passwdInfo)
}

function applyWinZipAesHeadResponse(response, request) {
  const { zipInfo, zipPlainRange } = request
  if (!zipInfo || !zipPlainRange) return
  response.statusCode = zipPlainRange.hasRange ? 206 : 200
  if (zipPlainRange.hasRange) {
    response.setHeader('content-range', `bytes ${zipPlainRange.start}-${zipPlainRange.end}/${zipInfo.plainSize}`)
  } else {
    response.removeHeader('content-range')
  }
  response.setHeader('accept-ranges', 'bytes')
  response.setHeader('content-length', String(Math.max(0, zipPlainRange.end - zipPlainRange.start + 1)))
  response.setHeader('content-type', getMimeByName(request.zipVirtualName || request.url))
}

const proxyRouter = new Router()
const app = new Koa()
// compatible ncc and pkg
const pkgDirPath = path.dirname(process.argv[1])

app.use(staticServer(pkgDirPath, 'public'))
app.use(globalHandle)
// bodyparser解析body
const bodyparserMw = bodyparser({ enableTypes: ['json', 'form', 'text'] })

// ======================/proxy是实现本服务的业务==============================
// 短地址
encApiRouter.redirect('/index', '/public/index.html', 302)
app.use(encApiRouter.routes()).use(encApiRouter.allowedMethods())

// ======================下面是实现webdav代理的业务==============================

// 可能是302跳转过来的下载的,/redirect?key=34233&decode=0
proxyRouter.all('/redirect/:key', async (ctx) => {
  const request = ctx.req
  const response = ctx.res
  // 这里还是要encodeURIComponent ，因为http服务器会自动对url进行decodeURIComponent
  const data = await levelDB.getValue(ctx.params.key)
  if (data === null) {
    ctx.body = 'no found'
    return
  }
  const {
    passwdInfo,
    redirectUrl,
    fileSize,
    virtualName,
    zipInfo: cachedZipInfoData,
    sevenZipAesCbcInfo: cachedSevenZipAesCbcInfoData,
  } = data
  // 要定位请求文件的位置 bytes=98304-
  const range = request.headers.range
  const start = getRangeStart(range)
  // 设置请求地址和是否要解密
  const decode = ctx.query.decode
  // 修改百度头
  if (~redirectUrl.indexOf('baidupcs.com')) {
    request.headers['User-Agent'] = 'pan.baidu.com'
  }
  request.url = decodeURIComponent(ctx.query.lastUrl)
  request.urlAddr = redirectUrl
  delete request.headers.host
  // aliyun不允许这个referer，不然会出现403
  delete request.headers.referer
  request.passwdInfo = passwdInfo
  // 123网盘和天翼网盘多次302
  request.fileSize = fileSize
  // authorization 是alist网页版的token，不是webdav的，这里修复天翼云无法获取资源的问题
  delete request.headers.authorization

  // 默认判断路径来识别是否要解密，如果有decode参数，那么则按decode来处理，这样可以让用户手动处理是否解密？(那还不如直接在alist下载)
  const shouldDecode = decode ? decode !== '0' : passwdInfo.enable && pathExec(passwdInfo.encPath, request.url)
  let decryptTransform = null
  request.zipVirtualName = virtualName
  request.sevenZipAesCbcVirtualName = virtualName
  if (shouldDecode) {
    let flowEnc = null
    if (isWinZipAesEncType(passwdInfo.encType)) {
      flowEnc = await prepareWinZipAesDecrypt(request, passwdInfo, fileSize, range, deserializeWinZipAesZipInfo(cachedZipInfoData))
    } else if (isSevenZipAesCbcEncType(passwdInfo.encType)) {
      flowEnc = await prepareSevenZipAesCbcDecrypt(
        request,
        passwdInfo,
        fileSize,
        range,
        deserializeSevenZipAesCbcInfo(cachedSevenZipAesCbcInfoData)
      )
    } else {
      flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, fileSize)
      if (start) {
        await flowEnc.setPosition(start)
      }
    }
    decryptTransform = flowEnc.decryptTransform()
  }
  // 请求实际服务资源
  await httpProxy(request, response, null, decryptTransform)
  logger.info('----finish redirect---', decode, request.urlAddr, decryptTransform === null)
})

// 预处理 request，处理地址，加密钥匙等
function preProxy(webdavConfig, isWebdav) {
  // 必包变量
  // let authorization = isWebdav
  return async (ctx, next) => {
    const { serverHost, serverPort, https } = webdavConfig
    const request = ctx.req
    if (isWebdav) {
      // 不能把authorization缓存起来，单线程
      request.isWebdav = isWebdav
      // request.headers.authorization = request.headers.authorization ? (authorization = request.headers.authorization) : authorization
    }
    // 原来的host保留，以后可能会用到
    request.selfHost = request.headers.host
    request.origin = request.headers.origin
    request.headers.host = serverHost + ':' + serverPort
    const protocol = https ? 'https' : 'http'
    request.urlAddr = `${protocol}://${request.headers.host}${request.url}`
    request.serverAddr = `${protocol}://${request.headers.host}`
    request.webdavConfig = webdavConfig
    await next()
  }
}
// webdav or http handle
async function proxyHandle(ctx, next) {
  const request = ctx.req
  const response = ctx.res
  const { passwdList } = request.webdavConfig
  const { headers } = request
  // 要定位请求文件的位置 bytes=98304-
  const range = headers.range
  const start = range ? range.replace('bytes=', '').split('-')[0] * 1 : 0
  // 检查路径是否满足加密要求，要拦截的路径可能有中文
  const { passwdInfo, pathInfo } = pathFindPasswd(passwdList, decodeURIComponent(request.url))
  logger.debug('@@@@passwdInfo', pathInfo)
  // fix webdav move file
  if (request.method.toLocaleUpperCase() === 'MOVE' && headers.destination) {
    let destination = headers.destination
    destination = request.serverAddr + destination.substring(destination.indexOf(path.dirname(request.url)), destination.length)
    request.headers.destination = destination
  }
  // 如果是上传文件，那么进行流加密，目前只支持webdav上传，如果alist页面有上传功能，那么也可以兼容进来
  if (request.method.toLocaleUpperCase() === 'PUT' && passwdInfo) {
    // 兼容macos的webdav客户端x-expected-entity-length
    const contentLength = headers['content-length'] || headers['x-expected-entity-length'] || 0
    request.fileSize = contentLength * 1
    // 需要知道文件长度，等于0 说明不用加密，这个来自webdav奇怪的请求
    if (request.fileSize === 0) {
      return await httpProxy(request, response)
    }
    const originalName = request.originalName || path.basename(decodeURIComponent(request.url.split('?')[0] || ''))
    setWinZipAesUploadSize(request, passwdInfo, request.fileSize, originalName)
    const sevenZipAesCbcPackageSize = setSevenZipAesCbcUploadSize(request, passwdInfo, request.fileSize, originalName)
    const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, request.fileSize, { originalName })
    const filePath = decodeURIComponent(request.url.split('?')[0] || '')
    await cacheGeneratedSevenZipAesCbcUploadInfo(
      passwdInfo,
      filePath,
      originalName,
      request.fileSize,
      sevenZipAesCbcPackageSize,
      flowEnc.encryptFlow.iv
    )
    return await httpProxy(request, response, flowEnc.encryptTransform())
  }
  // 如果是下载文件，那么就进行判断是否解密
  if ('GET,HEAD,POST'.includes(request.method.toLocaleUpperCase()) && passwdInfo) {
    // 根据文件路径来获取文件的大小
    const urlPath = ctx.req.url.split('?')[0]
    let filePath = urlPath
    // 如果是alist的话，那么必然有这个文件的size缓存（进过list就会被缓存起来）
    request.fileSize = 0
    // 这里需要处理掉/p 路径
    if (filePath.indexOf('/p/') === 0) {
      filePath = filePath.replace('/p/', '/')
    }
    if (filePath.indexOf('/d/') === 0) {
      filePath = filePath.replace('/d/', '/')
    }
    // 尝试获取文件信息，如果未找到相应的文件信息，则对文件名进行加密处理后重新尝试获取文件信息
    let fileInfo = await getFileInfo(filePath);
    const requestedFileName = decodeURIComponent(path.basename(filePath))

    if (fileInfo === null) {
      if (
        (!isWinZipAesEncType(passwdInfo.encType) || !requestedFileName.toLowerCase().endsWith('.zip')) &&
        (!isSevenZipAesCbcEncType(passwdInfo.encType) || !isSevenZipAesCbcFileName(requestedFileName))
      ) {
        const encodedRawFileName = encodeURIComponent(requestedFileName);
        const newFileName = convertRealName(passwdInfo.password, passwdInfo.encType, requestedFileName);

        filePath = filePath.replace(encodedRawFileName, newFileName);
        request.urlAddr = request.urlAddr.replace(encodedRawFileName, newFileName);

        fileInfo = await getFileInfo(filePath);
      }
    }
    if (isRawZipName(passwdInfo.password, passwdInfo.encType, requestedFileName)) {
      request.isExternalZipCandidate = true
    }
    if (isSevenZipAesCbcEncType(passwdInfo.encType) && isSevenZipAesCbcFileName(requestedFileName)) {
      request.isExternalSevenZipAesCbcCandidate = true
    }
    logger.info('@@getFileInfo:', filePath, fileInfo, request.urlAddr)
    if (
      request.isWebdav &&
      fileInfo &&
      isWinZipAesEncType(passwdInfo.encType) &&
      Number(fileInfo.size) < 1024 &&
      request.headers.authorization
    ) {
      const webdavFileInfo = await getWebdavFileInfo(request.urlAddr, request.headers.authorization)
      logger.info('@@webdavFileInfoRefresh:', filePath, webdavFileInfo)
      if (webdavFileInfo && webdavFileInfo.size * 1 > 0) {
        webdavFileInfo.path = filePath
        await cacheFileInfo(webdavFileInfo)
        fileInfo = webdavFileInfo
      }
    }
    if (fileInfo) {
      request.fileSize = fileInfo.size * 1
      if (fileInfo.externalZip) {
        request.isExternalZip = true
        request.zipVirtualName = fileInfo.zipInfo && fileInfo.zipInfo.innerName
      }
      if (fileInfo.externalSevenZipAesCbc && isUsableSevenZipAesCbcInfoCache(fileInfo, fileInfo.size, passwdInfo.password)) {
        request.isExternalSevenZipAesCbc = true
        request.sevenZipAesCbcVirtualName =
          fileInfo.sevenZipAesCbcInfo && fileInfo.sevenZipAesCbcInfo.innerName
      }
    } else if (request.headers.authorization) {
      // 这里要判断是否webdav进行请求, 这里默认就是webdav请求了
      const authorization = request.headers.authorization
      const webdavFileInfo = await getWebdavFileInfo(request.urlAddr, authorization)
      logger.info('@@webdavFileInfo:', filePath, webdavFileInfo)
      if (webdavFileInfo) {
        webdavFileInfo.path = filePath
        // 某些get请求返回的size=0，不要缓存起来
        if (webdavFileInfo.size * 1 > 0) {
          await cacheFileInfo(webdavFileInfo)
        }
        request.fileSize = webdavFileInfo.size * 1
        fileInfo = webdavFileInfo
      }
    }
    request.passwdInfo = passwdInfo
    // logger.info('@@@@request.filePath ', request.filePath, result)
    if (request.fileSize === 0) {
      // 说明不用加密
      return await httpProxy(request, response)
    }
    let flowEnc = null
    if (isWinZipAesEncType(passwdInfo.encType)) {
      if (request.isExternalZipCandidate && !(fileInfo && fileInfo.externalZip)) {
        const externalFileInfo = await prepareExternalWinZipAesZipInfo(
          request,
          fileInfo || {
            path: filePath,
            name: path.basename(filePath),
            is_dir: false,
            size: request.fileSize,
            zipVirtualName: path.basename(filePath),
          },
          request.urlAddr,
          request.headers,
          passwdInfo
        )
        if (!externalFileInfo || !externalFileInfo.zipInfo) {
          logger.info('@@ordinary zip passthrough:', filePath)
          return await httpProxy(request, response)
        }
        fileInfo = externalFileInfo
        request.isExternalZip = true
        request.zipVirtualName = externalFileInfo.zipInfo && externalFileInfo.zipInfo.innerName
      }
      const cachedZipInfo =
        isZipInfoCacheEnabled(passwdInfo) && isUsableWinZipAesZipInfoCache(fileInfo, request.fileSize)
          ? deserializeWinZipAesZipInfo(fileInfo && fileInfo.zipInfo)
          : null
      flowEnc = await prepareWinZipAesDecrypt(request, passwdInfo, request.fileSize, range, cachedZipInfo)
      if (
        isZipInfoCacheEnabled(passwdInfo) &&
        fileInfo &&
        request.zipInfo &&
        (!cachedZipInfo || Number(cachedZipInfo.totalSize) !== Number(request.fileSize))
      ) {
        await cacheFileInfo({
          ...fileInfo,
          plainSize: request.zipInfo.plainSize,
          zipInfo: serializeWinZipAesZipInfo(request.zipInfo),
          externalZip: fileInfo.externalZip || request.isExternalZipCandidate,
          zipVirtualName: fileInfo.zipVirtualName || (request.isExternalZipCandidate ? path.basename(filePath) : undefined),
        }, getZipInfoCacheExpireSeconds(passwdInfo))
      }
      if (request.method.toLocaleUpperCase() === 'HEAD') {
        applyWinZipAesHeadResponse(response, request)
        response.end()
        return
      }
      if (request.isWebdav) {
        request.followRemoteRedirect = true
      }
    } else if (isSevenZipAesCbcEncType(passwdInfo.encType)) {
      if (!request.isExternalSevenZipAesCbc && !request.isExternalSevenZipAesCbcCandidate) {
        logger.info('@@7z AES-CBC passthrough:', filePath)
        return await httpProxy(request, response)
      }
      if (request.isExternalSevenZipAesCbcCandidate && !request.isExternalSevenZipAesCbc) {
        const externalFileInfo = await prepareExternalSevenZipAesCbcInfo(
          request,
          fileInfo || {
            path: filePath,
            name: path.basename(filePath),
            is_dir: false,
            size: request.fileSize,
            sevenZipAesCbcVirtualName: path.basename(filePath),
          },
          request.urlAddr,
          request.headers,
          passwdInfo
        )
        if (!externalFileInfo || !externalFileInfo.sevenZipAesCbcInfo) {
          logger.info('@@ordinary 7z passthrough:', filePath)
          return await httpProxy(request, response)
        }
        fileInfo = externalFileInfo
        request.isExternalSevenZipAesCbc = true
        request.sevenZipAesCbcVirtualName =
          externalFileInfo.sevenZipAesCbcInfo && externalFileInfo.sevenZipAesCbcInfo.innerName
      }
      const cachedSevenZipAesCbcInfo = isZipInfoCacheEnabled(passwdInfo) && isUsableSevenZipAesCbcInfoCache(fileInfo, request.fileSize, passwdInfo.password)
        ? deserializeSevenZipAesCbcInfo(fileInfo && fileInfo.sevenZipAesCbcInfo)
        : null
      flowEnc = await prepareSevenZipAesCbcDecrypt(
        request,
        passwdInfo,
        request.fileSize,
        range,
        cachedSevenZipAesCbcInfo
      )
      if (
        isZipInfoCacheEnabled(passwdInfo) &&
        fileInfo &&
        request.sevenZipAesCbcInfo &&
        (!cachedSevenZipAesCbcInfo || Number(cachedSevenZipAesCbcInfo.totalSize) !== Number(request.fileSize))
      ) {
        await cacheFileInfo({
          ...fileInfo,
          plainSize: request.sevenZipAesCbcInfo.plainSize,
          sevenZipAesCbcInfo: serializeSevenZipAesCbcInfo(request.sevenZipAesCbcInfo),
          externalSevenZipAesCbc: fileInfo.externalSevenZipAesCbc || request.isExternalSevenZipAesCbcCandidate,
          sevenZipAesCbcPasswordHash: getSevenZipAesCbcPasswordHash(passwdInfo.password),
          sevenZipAesCbcVirtualName:
            fileInfo.sevenZipAesCbcVirtualName ||
            (request.isExternalSevenZipAesCbcCandidate ? path.basename(filePath) : undefined),
        }, getZipInfoCacheExpireSeconds(passwdInfo))
      }
      if (request.method.toLocaleUpperCase() === 'HEAD') {
        response.statusCode = request.sevenZipAesCbcPlainRange.hasRange ? 206 : 200
        applySevenZipAesCbcResponseHeaders(response, request)
        response.end()
        return
      }
      if (request.isWebdav) {
        request.followRemoteRedirect = true
      }
    } else {
      flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, request.fileSize)
      if (start) {
        await flowEnc.setPosition(start)
      }
    }
    return await httpProxy(request, response, null, flowEnc.decryptTransform())
  }
  await httpProxy(request, response)
}

// 初始化webdav路由，这里可以优化成动态路由，只不过没啥必要，修改配置后直接重启就好了
webdavServer.forEach((webdavConfig) => {
  if (webdavConfig.enable) {
    proxyRouter.all(new RegExp(webdavConfig.path), preProxy(webdavConfig, true), encDavHandle, proxyHandle)
  }
})

/* =================================== 单独处理alist的逻辑 ====================================== */

// 单独处理alist的所有/dav
proxyRouter.all(/^\/dav\/*/, preProxy(alistServer, true), encDavHandle, proxyHandle)

// 其他的代理request预处理，处理要跳转的路径等
proxyRouter.all(/\/*/, preProxy(alistServer, false))
// check enc filename
proxyRouter.use(encNameRouter.routes()).use(encNameRouter.allowedMethods())

// 处理文件下载的302跳转
proxyRouter.get(/^\/d\/*/, proxyHandle)
// 文件直接下载
proxyRouter.get(/^\/p\/*/, proxyHandle)

// 处理在线视频播放的问题，修改它的返回播放地址 为本代理的地址。
proxyRouter.all('/api/fs/get', bodyparserMw, async (ctx, next) => {
  const { path } = ctx.request.body
  // 判断打开的文件是否要解密，要解密则替换url，否则透传
  ctx.req.reqBody = JSON.stringify(ctx.request.body)

  const respBody = await httpClient(ctx.req)
  const result = JSON.parse(respBody)
  const { headers } = ctx.req
  const { passwdInfo } = pathFindPasswd(alistServer.passwdList, path)

  if (passwdInfo && result.code === 200 && result.data && result.data.raw_url) {
    // 修改返回的响应，匹配到要解密，就302跳转到本服务上进行代理流量
    logger.info('@@getFile ', path, ctx.req.reqBody, result)
    const remoteFileSize = result.data.size
    let zipInfo = null
    let sevenZipAesCbcInfo = null
    if (isWinZipAesEncType(passwdInfo.encType)) {
      if (ctx.req.isExternalZip && ctx.req.cachedExternalZipInfo) {
        zipInfo = deserializeWinZipAesZipInfo(ctx.req.cachedExternalZipInfo)
      } else if (ctx.req.isExternalZipCandidate) {
        const cachedOrParsed = await prepareExternalWinZipAesZipInfo(
          ctx.req,
          {
            path,
            name: path.split('/').pop(),
            is_dir: false,
            size: remoteFileSize,
            zipVirtualName: path.split('/').pop(),
          },
          result.data.raw_url,
          ctx.req.headers,
          passwdInfo,
          { stripAuth: true }
        )
        if (!cachedOrParsed || !cachedOrParsed.zipInfo) {
          ctx.body = result
          return
        }
        zipInfo = deserializeWinZipAesZipInfo(cachedOrParsed.zipInfo)
      } else {
        const cachedOrParsed = await prepareManagedWinZipAesZipInfo(
          ctx.req,
          passwdInfo,
          {
            ...result.data,
            path,
            name: path.split('/').pop(),
            is_dir: false,
            size: remoteFileSize,
            zipVirtualName: decodeURIComponent((ctx.req.encVirtualPath || path).split('/').pop() || ''),
          },
          result.data.raw_url,
          ctx.req.headers,
          { stripAuth: true }
        )
        zipInfo = deserializeWinZipAesZipInfo(cachedOrParsed.zipInfo)
      }
      result.data.size = zipInfo.plainSize
    } else if (isSevenZipAesCbcEncType(passwdInfo.encType)) {
      const isSevenZipAesCbcTarget =
        ctx.req.isExternalSevenZipAesCbc ||
        ctx.req.isExternalSevenZipAesCbcCandidate ||
        isSevenZipAesCbcFileName(path.split('/').pop())
      if (!isSevenZipAesCbcTarget) {
        ctx.body = result
        return
      }
      if (ctx.req.isExternalSevenZipAesCbc && ctx.req.cachedExternalSevenZipAesCbcInfo) {
        sevenZipAesCbcInfo = deserializeSevenZipAesCbcInfo(ctx.req.cachedExternalSevenZipAesCbcInfo)
      } else if (ctx.req.isExternalSevenZipAesCbcCandidate || isSevenZipAesCbcFileName(path.split('/').pop())) {
        const cachedOrParsed = await prepareExternalSevenZipAesCbcInfo(
          ctx.req,
          {
            path,
            name: path.split('/').pop(),
            is_dir: false,
            size: remoteFileSize,
            sevenZipAesCbcVirtualName: path.split('/').pop(),
          },
          result.data.raw_url,
          ctx.req.headers,
          passwdInfo,
          { stripAuth: true }
        )
        if (!cachedOrParsed || !cachedOrParsed.sevenZipAesCbcInfo) {
          ctx.body = result
          return
        }
        sevenZipAesCbcInfo = deserializeSevenZipAesCbcInfo(cachedOrParsed.sevenZipAesCbcInfo)
      } else {
        const cachedOrParsed = await prepareManagedSevenZipAesCbcInfo(
          ctx.req,
          passwdInfo,
          {
            ...result.data,
            path,
            name: path.split('/').pop(),
            is_dir: false,
            size: remoteFileSize,
            sevenZipAesCbcVirtualName: decodeURIComponent((ctx.req.encVirtualPath || path).split('/').pop() || ''),
          },
          result.data.raw_url,
          ctx.req.headers,
          { stripAuth: true }
        )
        sevenZipAesCbcInfo = deserializeSevenZipAesCbcInfo(cachedOrParsed.sevenZipAesCbcInfo)
      }
      result.data.size = sevenZipAesCbcInfo.plainSize
    }
    const key = crypto.randomUUID()
    const virtualName = decodeURIComponent((ctx.req.encVirtualPath || path).split('/').pop() || '')
    const previewName =
      (ctx.req.isExternalZip || ctx.req.isExternalZipCandidate) && zipInfo
        ? zipInfo.innerName
        : (ctx.req.isExternalSevenZipAesCbc || ctx.req.isExternalSevenZipAesCbcCandidate || isSevenZipAesCbcFileName(path.split('/').pop())) && sevenZipAesCbcInfo
          ? sevenZipAesCbcInfo.innerName
          : virtualName
    await levelDB.setExpire(
      key,
      {
        redirectUrl: result.data.raw_url,
        passwdInfo,
        fileSize: remoteFileSize,
        virtualName: previewName,
        zipInfo: serializeWinZipAesZipInfo(zipInfo),
        sevenZipAesCbcInfo: serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo),
      },
      60 * 60 * 72
    ) // 缓存起来，默认3天，足够下载和观看了
    result.data.raw_url = `${
      headers.origin || (headers['x-forwarded-proto'] || ctx.protocol) + '://' + ctx.req.selfHost
    }/redirect/${key}?decode=1&lastUrl=${encodeURIComponent(path)}`
    if (previewName) {
      result.data.type = getAListFileTypeByName(previewName)
    }
    if (isWinZipAesEncType(passwdInfo.encType) || isSevenZipAesCbcEncType(passwdInfo.encType) || result.data.provider === 'AliyundriveOpen') {
      result.data.provider = 'Local'
    }
  }
  ctx.body = result
})

// 缓存alist的文件信息
proxyRouter.all('/api/fs/list', bodyparserMw, async (ctx, next) => {
  const { path } = ctx.request.body
  // 判断打开的文件是否要解密，要解密则替换url，否则透传
  ctx.req.reqBody = JSON.stringify(ctx.request.body)
  const respBody = await httpClient(ctx.req)
  // logger.info('@@@respBody', respBody)
  const result = JSON.parse(respBody)
  if (!result.data) {
    ctx.body = result
    return
  }
  const content = result.data.content
  if (!content) {
    ctx.body = result
    return
  }
  for (let i = 0; i < content.length; i++) {
    const fileInfo = content[i]
    fileInfo.path = path + '/' + fileInfo.name
    // 这里要注意闭包问题，mad
    // logger.debug('@@cacheFileInfo', fileInfo.path)
    await cacheFileInfo(fileInfo)
  }
  // waiting cacheFileInfo a moment
  if (content.length > 100) {
    await sleep(50)
  }
  logger.info('@@@fs/list', content.length)
  ctx.body = result
})

// that is not work when upload txt file if enable encName
proxyRouter.put('/api/fs/put-back', async (ctx, next) => {
  const request = ctx.req
  const { headers, webdavConfig } = request
  const contentLength = headers['content-length'] || 0
  request.fileSize = contentLength * 1

  const uploadPath = headers['file-path'] ? decodeURIComponent(headers['file-path']) : '/-'
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, uploadPath)
  if (passwdInfo) {
    const originalName = path.basename(uploadPath)
    let filePath = uploadPath
    if (isSevenZipAesCbcEncType(passwdInfo.encType)) {
      filePath = path.dirname(uploadPath) + '/' + getSevenZipAesCbcPackageName(originalName)
      headers['file-path'] = encodeURIComponent(filePath)
    }
    setWinZipAesUploadSize(request, passwdInfo, request.fileSize, originalName)
    const sevenZipAesCbcPackageSize = setSevenZipAesCbcUploadSize(request, passwdInfo, request.fileSize, originalName)
    const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, request.fileSize, { originalName })
    await cacheGeneratedSevenZipAesCbcUploadInfo(
      passwdInfo,
      filePath,
      originalName,
      request.fileSize,
      sevenZipAesCbcPackageSize,
      flowEnc.encryptFlow.iv
    )
    return await httpProxy(ctx.req, ctx.res, flowEnc.encryptTransform())
  }
  return await httpProxy(ctx.req, ctx.res)
})

// 修复alist 图标不显示的问题
proxyRouter.all(/^\/images\/*/, async (ctx, next) => {
  delete ctx.req.headers.host
  return await httpProxy(ctx.req, ctx.res)
})

// 初始化alist的路由
proxyRouter.all(new RegExp(alistServer.path), async (ctx, next) => {
  let respBody = await httpClient(ctx.req, ctx.res)
  respBody = respBody.replace(
    '<body>',
    `<body>
    <div style="position: fixed;z-index:10010; top:7px; margin-left: 50%">
      <a target="_blank" href="/index">
        <div style="width:40px;height:40px;margin-left: -20px">
          <img style="width:40px;height:40px;" src="/public/logo.png" />
          <div style="margin: -7px 2px;">
            <span style="color:gray;font-size:11px">V.${version}</span>
          </div>
        </div>
      </a>
    </div>`
  )
  ctx.body = respBody
})
// 使用路由控制
app.use(proxyRouter.routes()).use(proxyRouter.allowedMethods())

// 配置创建好了，就启动 else {
const server = http.createServer(app.callback())
server.maxConnections = 1000
server.listen(port, () => logger.info('服务启动成功: ' + port))
setInterval(() => {
  logger.debug('server_connections', server._connections, Date.now())
}, 600 * 1000)
