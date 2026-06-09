'use strict'

import { pathFindPasswd, convertRealName, convertShowName, getOrigName, isEncryptedZipName, isOrigName, isRawZipName } from './utils/commonUtil'
import { cacheFileInfo, getFileInfo } from './dao/fileDao'
import { logger } from './common/logger'
import path from 'path'
import { httpClient } from './utils/httpClient'
import { XMLParser } from 'fast-xml-parser'
import WinZipAesZip, {
  isWinZipAesEncType,
  parseWinZipAesZipInfoFromRemote,
  serializeWinZipAesZipInfo,
} from './utils/winZipAesZip'
// import { escape } from 'querystring'

async function sleep(time) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, time || 3000)
  })
}

// bodyparser解析body
const parser = new XMLParser({ removeNSPrefix: true })

function getProp(fileInfo) {
  if (fileInfo.propstat instanceof Array) return fileInfo.propstat[0].prop
  return fileInfo.propstat.prop
}

function getFileNameForShow(fileInfo, passwdInfo) {
  let getcontentlength = -1
  const href = fileInfo.href
  const fileName = path.basename(href)
  const prop = getProp(fileInfo)
  if (prop) getcontentlength = prop.getcontentlength
  // logger.debug('@@fileInfo_show', JSON.stringify(fileInfo))
  // is not dir
  if (getcontentlength !== undefined && getcontentlength > -1) {
    const showName = isWinZipAesEncType(passwdInfo.encType)
      ? isEncryptedZipName(passwdInfo.password, passwdInfo.encType, fileName)
        ? convertShowName(passwdInfo.password, passwdInfo.encType, href)
        : fileName
      : convertShowName(passwdInfo.password, passwdInfo.encType, href)
    return { fileName, showName }
  }
  // cache this folder info
  return {}
}

function cacheWebdavFileInfo(fileInfo) {
  let getcontentlength = -1
  const href = fileInfo.href
  const fileName = path.basename(href)
  const prop = getProp(fileInfo)
  if (prop) getcontentlength = prop.getcontentlength
  // logger.debug('@@@cacheWebdavFileInfo', href, fileName)
  // it is a file
  if (getcontentlength !== undefined && getcontentlength > -1) {
    const fileDetail = { path: href, name: fileName, is_dir: false, size: getcontentlength }
    cacheFileInfo(fileDetail)
    return fileDetail
  }
  // cache this folder info
  const fileDetail = { path: href, name: fileName, is_dir: true, size: 0 }
  cacheFileInfo(fileDetail)
  return fileDetail
}

function xmlEscapeText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&gt;')
}

function replaceOnce(text, from, to) {
  const index = text.indexOf(from)
  if (index < 0) return text
  return text.slice(0, index) + to + text.slice(index + from.length)
}

async function prepareWinZipAesWebdavFileInfo(fileDetail, request, passwdInfo) {
  if (!fileDetail || fileDetail.is_dir || fileDetail.zipInfo) return fileDetail
  if (!String(fileDetail.name || '').toLowerCase().endsWith('.zip')) return fileDetail
  const isManagedZipName = isEncryptedZipName(passwdInfo.password, passwdInfo.encType, fileDetail.name)
  const cachedFileInfo = await getFileInfo(fileDetail.path)
  if (
    cachedFileInfo &&
    cachedFileInfo.zipInfo &&
    isWinZipAesEncType(cachedFileInfo.zipInfo.encType) &&
    Number(cachedFileInfo.size) === Number(fileDetail.size) &&
    !!cachedFileInfo.externalZip === !isManagedZipName
  ) {
    return {
      ...fileDetail,
      plainSize: cachedFileInfo.plainSize,
      zipInfo: cachedFileInfo.zipInfo,
      externalZip: cachedFileInfo.externalZip,
      zipVirtualName: cachedFileInfo.zipVirtualName,
    }
  }
  try {
    const zipInfo = await parseWinZipAesZipInfoFromRemote(request.urlAddr, request.headers, fileDetail.size)
    const nextFileInfo = {
      ...fileDetail,
      plainSize: zipInfo.plainSize,
      zipInfo: serializeWinZipAesZipInfo(zipInfo),
      externalZip: !isManagedZipName,
      zipVirtualName: isManagedZipName ? undefined : fileDetail.name,
    }
    await cacheFileInfo(nextFileInfo)
    return nextFileInfo
  } catch (e) {
    return fileDetail
  }
}

function rewriteWebdavContentLength(respBody, fileInfo, plainSize) {
  const prop = getProp(fileInfo)
  if (!prop || prop.getcontentlength === undefined || plainSize === undefined) return respBody
  return replaceOnce(
    respBody,
    `<D:getcontentlength>${prop.getcontentlength}</D:getcontentlength>`,
    `<D:getcontentlength>${plainSize}</D:getcontentlength>`
  )
}

function isWebdavFileRequest(url, fileName) {
  return !url.endsWith('/') && !!path.extname(decodeURIComponent(fileName || ''))
}

function getRequestRealName(passwdInfo, url, fileInfo) {
  const fileName = path.basename(url)
  if (fileInfo && fileInfo.externalZip) return fileInfo.name || fileName
  if (isRawZipName(passwdInfo.password, passwdInfo.encType, fileName)) return fileName
  if (isOrigName(fileName)) return getOrigName(fileName)
  return convertRealName(passwdInfo.password, passwdInfo.encType, url)
}

function getExternalZipRenameTarget(fileInfo, destinationName) {
  if (!fileInfo || !fileInfo.externalZip) return destinationName
  if (path.extname(destinationName).toLowerCase() !== '.zip') return destinationName
  const innerExt = path.extname((fileInfo.zipInfo && fileInfo.zipInfo.innerName) || '')
  return innerExt ? path.basename(destinationName, '.zip') + innerExt : destinationName
}

// 拦截全部
const handle = async (ctx, next) => {
  const request = ctx.req
  const { passwdList } = request.webdavConfig
  const { passwdInfo } = pathFindPasswd(passwdList, decodeURIComponent(request.url))
  if (ctx.method.toLocaleUpperCase() === 'PROPFIND' && passwdInfo && passwdInfo.encName) {
    // check dir, convert url
    const url = request.url
    if (passwdInfo && passwdInfo.encName) {
      // check dir, convert url
      const reqFileName = path.basename(url)
      // cache source file info, realName has execute encodeUrl()，this '(' '+' can't encodeUrl.
      const isManagedZipName = isEncryptedZipName(passwdInfo.password, passwdInfo.encType, reqFileName)
      const realName =
        isManagedZipName || !isRawZipName(passwdInfo.password, passwdInfo.encType, reqFileName)
          ? convertRealName(passwdInfo.password, passwdInfo.encType, url)
          : reqFileName
      // when the name contain the + , ! ,
      const sourceUrl = path.dirname(url) + '/' + realName
      const sourceFileInfo = await getFileInfo(sourceUrl)
      logger.debug('@@@sourceFileInfo', sourceFileInfo, reqFileName, realName, url, sourceUrl)
      // it is file, convert file name
      if ((sourceFileInfo && !sourceFileInfo.is_dir) || isWebdavFileRequest(url, reqFileName)) {
        request.isManagedZipName = isManagedZipName
        request.url = path.dirname(request.url) + '/' + realName
        request.urlAddr = path.dirname(request.urlAddr) + '/' + realName
      }
    }
    // decrypt file name
    let respBody = await httpClient(ctx.req, ctx.res)
    const respData = parser.parse(respBody)
    // convert file name for show
    if (respData.multistatus) {
      const respJson = respData.multistatus.response
      if (respJson instanceof Array) {
        // console.log('@@respJsonArray', respJson)
        for (const fileInfo of respJson) {
          // cache real file info，include forder name
          let fileDetail = cacheWebdavFileInfo(fileInfo)
          if (isWinZipAesEncType(passwdInfo.encType) && fileDetail && !fileDetail.is_dir) {
            const oldUrlAddr = request.urlAddr
            request.urlAddr = request.serverAddr + fileDetail.path
            fileDetail = await prepareWinZipAesWebdavFileInfo(fileDetail, request, passwdInfo)
            request.urlAddr = oldUrlAddr
            respBody = rewriteWebdavContentLength(respBody, fileInfo, fileDetail.plainSize)
          }
          if (passwdInfo && passwdInfo.encName) {
            const { fileName, showName } = getFileNameForShow(fileInfo, passwdInfo)
            // logger.debug('@@getFileNameForShow1 list', passwdInfo.password, fileName, decodeURI(fileName), showName)
            if (fileName) {
              const showXmlName = xmlEscapeText(showName)
              respBody = respBody.replace(`${fileName}</D:href>`, `${encodeURI(showXmlName)}</D:href>`)
              respBody = respBody.replace(`${decodeURI(fileName)}</D:displayname>`, `${decodeURI(showXmlName)}</D:displayname>`)
            }
          }
        }
        // waiting cacheWebdavFileInfo a moment
        await sleep(50)
      } else if (passwdInfo && passwdInfo.encName) {
        const fileInfo = respJson
        let fileDetail = cacheWebdavFileInfo(fileInfo)
        if (isWinZipAesEncType(passwdInfo.encType) && fileDetail && !fileDetail.is_dir) {
          fileDetail = await prepareWinZipAesWebdavFileInfo(fileDetail, request, passwdInfo)
          respBody = rewriteWebdavContentLength(respBody, fileInfo, fileDetail.plainSize)
        }
        const { fileName, showName } = getFileNameForShow(fileInfo, passwdInfo)
        // logger.debug('@@getFileNameForShow2 file', fileName, showName, url, respJson.propstat)
        if (fileName) {
          const showXmlName = xmlEscapeText(showName)
          respBody = respBody.replace(`${fileName}</D:href>`, `${encodeURI(showXmlName)}</D:href>`)
          respBody = respBody.replace(`${decodeURI(fileName)}</D:displayname>`, `${decodeURI(showXmlName)}</D:displayname>`)
        }
      }
    }
    // 检查数据兼容的问题，优先XML对比。
    // logger.debug('@@respJsxml', respBody, ctx.headers)
    // const resultBody = parser.parse(respBody)
    // logger.debug('@@respJSONData2', ctx.res.statusCode, JSON.stringify(resultBody))

    if (ctx.res.statusCode === 404) {
      // fix rclone propfind 404 ，because rclone copy will get error 501
      ctx.res.end(respBody)
      return
    }
    // fix webdav 401 bug，群晖遇到401不能使用 ctx.res.end(respBody)，而rclone遇到404只能使用ctx.res.end(respBody),神奇的bug
    ctx.status = ctx.res.statusCode
    ctx.body = respBody
    return
  }
  // copy or move file
  if ('COPY,MOVE'.includes(request.method.toLocaleUpperCase()) && passwdInfo && passwdInfo.encName) {
    const url = request.url
    const fileInfo = await getFileInfo(url)
    const realName = getRequestRealName(passwdInfo, url, fileInfo)
    const destinationName = path.basename(decodeURIComponent(request.headers.destination || ''))
    const destinationRealName = convertRealName(passwdInfo.password, passwdInfo.encType, getExternalZipRenameTarget(fileInfo, destinationName))
    request.headers.destination = path.dirname(request.headers.destination) + '/' + encodeURI(destinationRealName)
    request.url = path.dirname(request.url) + '/' + encodeURI(realName)
    request.urlAddr = path.dirname(request.urlAddr) + '/' + encodeURI(realName)
  }

  // upload file
  if ('GET,PUT,DELETE'.includes(request.method.toLocaleUpperCase()) && passwdInfo && passwdInfo.encName) {
    const url = request.url
    // check dir, convert url
    const fileName = path.basename(url)
    const cachedFileInfo = await getFileInfo(url)
    const realName = getRequestRealName(passwdInfo, url, cachedFileInfo)
    // maybe from aliyundrive, check this req url while get file list from enc folder
    if (url.endsWith('/') && 'GET,DELETE'.includes(request.method.toLocaleUpperCase())) {
      let respBody = await httpClient(ctx.req, ctx.res)
      if(request.method.toLocaleUpperCase() === 'GET'){
        const aurlArr = respBody.match(/href="[^"]*"/g)
        // logger.debug('@@aurlArr', aurlArr)
        if (aurlArr && aurlArr.length) {
          for (let urlStr of aurlArr) {
            urlStr = urlStr.replace('href="', '').replace('"', '')
            const aurl = decodeURIComponent(urlStr.replace('href="', '').replace('"', ''))
            const baseUrl = decodeURIComponent(url)
            if (aurl.includes(baseUrl)) {
              const fileName = path.basename(aurl)
              const showName = convertShowName(passwdInfo.password, passwdInfo.encType, fileName)
              logger.debug('@@aurl', urlStr, showName)
              respBody = respBody.replace(path.basename(urlStr), encodeURI(showName)).replace(fileName, showName)
            }
          }
        }
      }
      ctx.res.end(respBody)
      return
    }

    // console.log('@@convert file name', fileName, realName)
    if (isWinZipAesEncType(passwdInfo.encType)) {
      request.isExternalZip = cachedFileInfo && cachedFileInfo.externalZip
      request.isExternalZipCandidate = !request.isExternalZip && isRawZipName(passwdInfo.password, passwdInfo.encType, fileName)
      request.originalName = decodeURIComponent(fileName)
      request.zipVirtualName =
        request.isExternalZip && cachedFileInfo.zipInfo
          ? cachedFileInfo.zipInfo.innerName
          : request.isExternalZipCandidate
            ? undefined
            : decodeURIComponent(fileName)
    }
    request.url = path.dirname(request.url) + '/' + realName
    request.urlAddr = path.dirname(request.urlAddr) + '/' + realName
    if (request.method.toLocaleUpperCase() !== 'PUT') {
      await next()
      return
    }
    // cache file before upload in next(), rclone cmd 'copy' will PROPFIND this file when the file upload success right now
    const contentLength = request.headers['content-length'] || request.headers['x-expected-entity-length'] || 0
    const fileSize = isWinZipAesEncType(passwdInfo.encType)
      ? WinZipAesZip.packageSize(contentLength * 1, { originalName: fileName })
      : contentLength
    const fileDetail = { path: path.dirname(url) + '/' + realName, name: realName, is_dir: false, size: fileSize }
    logger.info('@@@put url', url)
    // 在页面上传文件，rclone会重复上传，所以要进行缓存文件信息，也不能在next() 因为rclone copy命令会出异常
    await cacheFileInfo(fileDetail)
  }
  await next()
}

export default handle
