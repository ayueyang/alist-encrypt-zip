'use strict'

import Router from 'koa-router'
import bodyparser from 'koa-bodyparser'
import {
  encodeName,
  pathFindPasswd,
  convertShowName,
  convertRealName,
  getAListFileTypeByName,
  getOrigName,
  isEncryptedZipName,
  isOrigName,
} from './utils/commonUtil'
import path from 'path'
import { httpClient, httpProxy } from './utils/httpClient'
import FlowEnc from './utils/flowEnc'
import { logger } from './common/logger'
import { cacheFileInfo, getFileInfo } from './dao/fileDao'
import WinZipAesZip, { isWinZipAesEncType } from './utils/winZipAesZip'
import { enqueueExternalWinZipAesZipProbe } from './utils/winZipAesZipCache'

// bodyparser解析body
const bodyparserMw = bodyparser({ enableTypes: ['json', 'form', 'text'] })

const encNameRouter = new Router()
const origPrefix = 'orig_'

function getEncryptedFileName(passwdInfo, fileName) {
  const baseName = path.basename(fileName)
  if (isWinZipAesEncType(passwdInfo.encType)) {
    return convertRealName(passwdInfo.password, passwdInfo.encType, baseName)
  }
  const ext = passwdInfo.encSuffix || path.extname(baseName)
  const encName = encodeName(passwdInfo.password, passwdInfo.encType, baseName)
  return encName + ext
}

function getZipPreviewName(fileInfo) {
  return fileInfo.showName || fileInfo.name
}

async function getCachedFileInfoByPath(filePath) {
  return (await getFileInfo(encodeURIComponent(filePath))) || (await getFileInfo(filePath))
}

function isRawZipName(passwdInfo, fileName) {
  return (
    isWinZipAesEncType(passwdInfo.encType) &&
    String(fileName || '').toLowerCase().endsWith('.zip') &&
    !isEncryptedZipName(passwdInfo.password, passwdInfo.encType, fileName)
  )
}

function getRequestRealName(passwdInfo, fileName, fileInfo) {
  if (fileInfo && fileInfo.externalZip) {
    return fileInfo.name || fileName
  }
  if (isRawZipName(passwdInfo, fileName)) {
    return fileName
  }
  return isOrigName(fileName) ? getOrigName(fileName) : convertRealName(passwdInfo.password, passwdInfo.encType, fileName)
}

function getShowName(passwdInfo, rawName, fileInfo) {
  if (fileInfo && fileInfo.externalZip) {
    return rawName
  }
  if (isRawZipName(passwdInfo, rawName)) {
    return rawName
  }
  return convertShowName(passwdInfo.password, passwdInfo.encType, rawName)
}

function getExternalZipRenameTarget(fileInfo, name) {
  if (!fileInfo || !fileInfo.externalZip) return name
  if (path.extname(name).toLowerCase() !== '.zip') return name
  const zipInfo = fileInfo.zipInfo || {}
  const innerExt = path.extname(zipInfo.innerName || '')
  return innerExt ? path.basename(name, '.zip') + innerExt : name
}

function joinUrlPath(dir, name) {
  return `${String(dir || '').replace(/\/$/, '')}/${name}`
}

function prepareWinZipAesListFileInfo(fileInfo, request, passwdInfo) {
  if (!isWinZipAesEncType(passwdInfo.encType) || fileInfo.is_dir || !String(fileInfo.name || '').toLowerCase().endsWith('.zip')) {
    return fileInfo
  }
  const isManaged = isEncryptedZipName(passwdInfo.password, passwdInfo.encType, fileInfo.name)
  if (isManaged) {
    fileInfo.name = convertShowName(passwdInfo.password, passwdInfo.encType, fileInfo.name)
    fileInfo.type = getAListFileTypeByName(fileInfo.name)
    return fileInfo
  }
  if (passwdInfo.zipAutoCache) {
    enqueueExternalWinZipAesZipProbe({
      fileInfo,
      urlAddr: request.serverAddr + fileInfo.path,
      headers: request.headers,
    })
  }
  return fileInfo
}

// 拦截全部
encNameRouter.all('/api/fs/list', async (ctx, next) => {
  console.log('@@encrypt file name ', ctx.req.url)
  await next()
  const result = ctx.body
  const { passwdList } = ctx.req.webdavConfig
  if (result.code === 200 && result.data) {
    const content = result.data.content
    if (!content) {
      return
    }
    for (let i = 0; i < content.length; i++) {
      const fileInfo = content[i]
      if (fileInfo.is_dir) {
        // TODO,这里应该要处理一下，加密文件夹
        continue
      }
      //  Check path if the file name needs to be encrypted
      const { passwdInfo } = pathFindPasswd(passwdList, decodeURI(fileInfo.path))
      if (passwdInfo && passwdInfo.encName) {
        prepareWinZipAesListFileInfo(fileInfo, ctx.req, passwdInfo)
        if (!isWinZipAesEncType(passwdInfo.encType)) {
          fileInfo.name = convertShowName(passwdInfo.password, passwdInfo.encType, fileInfo.name)
        }
      }
    }

    const coverNameMap = {} //根据不含后缀的视频文件名找到对应的含后缀的封面文件名
    const omitNames = [] //用于隐藏封面文件
    const { path } = JSON.parse(ctx.req.reqBody)
    result.data.content.forEach((fileInfo) => {
      if (fileInfo.is_dir) {
        return
      }
      if (fileInfo.type === 5) {
        coverNameMap[fileInfo.name.split('.')[0]] = fileInfo.name
      }
    })
    result.data.content.forEach((fileInfo) => {
      if (fileInfo.is_dir) {
        return
      }
      const coverName = coverNameMap[getZipPreviewName(fileInfo).split('.')[0]]
      if (fileInfo.type === 2 && coverName) {
        omitNames.push(coverName)
        fileInfo.thumb = `/d${path}/${coverName}`
      }
    })
    //不展示封面文件，也许可以添加个配置让用户选择是否展示封面源文件
    result.data.content = result.data.content.filter((fileInfo) => !omitNames.includes(fileInfo.name))
  }
})

// 处理网页上传文件
encNameRouter.put('/api/fs/put', async (ctx, next) => {
  const request = ctx.req
  const { headers, webdavConfig } = request
  const contentLength = headers['content-length'] || 0
  request.fileSize = contentLength * 1

  const uploadPath = headers['file-path'] ? decodeURIComponent(headers['file-path']) : '/-'
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, uploadPath)
  if (passwdInfo) {
    const fileName = path.basename(uploadPath)
    // you can custom Suffix
    if (passwdInfo.encName) {
      const realName = getEncryptedFileName(passwdInfo, fileName)
      const filePath = path.dirname(uploadPath) + '/' + realName
      console.log('@@@encfileName', fileName, uploadPath, filePath)
      headers['file-path'] = encodeURIComponent(filePath)
    }
    if (isWinZipAesEncType(passwdInfo.encType)) {
      const packageSize = WinZipAesZip.packageSize(request.fileSize, { originalName: fileName })
      headers['content-length'] = String(packageSize)
    }
    const flowEnc = new FlowEnc(passwdInfo.password, passwdInfo.encType, request.fileSize, { originalName: fileName })
    return await httpProxy(ctx.req, ctx.res, flowEnc.encryptTransform())
  }
  return await httpProxy(ctx.req, ctx.res)
})

// remove
encNameRouter.all('/api/fs/remove', bodyparserMw, async (ctx, next) => {
  const { dir, names } = ctx.request.body
  const { webdavConfig } = ctx.req
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, dir)
  // maybe a folder，remove anyway the name
  const fileNames = Object.assign([], names)
  if (passwdInfo && passwdInfo.encName) {
    for (const name of names) {
      if (isRawZipName(passwdInfo, name)) {
        continue
      }
      // is not enc name
      const realName = convertRealName(passwdInfo.password, passwdInfo.encType, name)
      fileNames.push(realName)
    }
  }
  const reqBody = { dir, names: fileNames }
  logger.info('@@reqBody remove', reqBody)
  ctx.req.reqBody = JSON.stringify(reqBody)
  // reset content-length length
  delete ctx.req.headers['content-length']
  const respBody = await httpClient(ctx.req)
  ctx.body = respBody
})

const copyOrMoveFile = async (ctx, next) => {
  const { dst_dir: dstDir, src_dir: srcDir, names } = ctx.request.body
  const { webdavConfig } = ctx.req
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, srcDir)
  let fileNames = []
  if (passwdInfo && passwdInfo.encName) {
    logger.info('@@move encName', passwdInfo.encName)
    for (const name of names) {
      // is not enc name
      if (name.indexOf(origPrefix) === 0) {
        const origName = name.replace(origPrefix, '')
        fileNames.push(origName)
        break
      }
      const cachedFileInfo = await getCachedFileInfoByPath(joinUrlPath(srcDir, name))
      if ((cachedFileInfo && cachedFileInfo.externalZip) || isRawZipName(passwdInfo, name)) {
        fileNames.push(name)
        continue
      }
      const newFileName = getEncryptedFileName(passwdInfo, name)
      fileNames.push(newFileName)
    }
  } else {
    fileNames = Object.assign([], names)
  }
  const reqBody = { dst_dir: dstDir, src_dir: srcDir, names: fileNames }
  ctx.req.reqBody = JSON.stringify(reqBody)
  logger.info('@@move reqBody', ctx.req.reqBody)
  // reset content-length length
  delete ctx.req.headers['content-length']
  const respBody = await httpClient(ctx.req)
  ctx.body = respBody
}

encNameRouter.all('/api/fs/move', bodyparserMw, copyOrMoveFile)
encNameRouter.all('/api/fs/copy', bodyparserMw, copyOrMoveFile)

encNameRouter.all('/api/fs/get', bodyparserMw, async (ctx, next) => {
  const { path: filePath } = ctx.request.body
  const { webdavConfig } = ctx.req
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, filePath)
  let fileInfo = null
  if (passwdInfo && passwdInfo.encName) {
    ctx.req.encVirtualPath = filePath
    // reset content-length length
    delete ctx.req.headers['content-length']
    // check fileName is not enc
    const fileName = path.basename(filePath)
    fileInfo = await getCachedFileInfoByPath(filePath)
    if (fileInfo && fileInfo.is_dir) {
      await next()
      return
    }
    if (isWinZipAesEncType(passwdInfo.encType)) {
      ctx.req.isExternalZip = !!(fileInfo && fileInfo.externalZip)
      ctx.req.isExternalZipCandidate = !ctx.req.isExternalZip && isRawZipName(passwdInfo, fileName)
      if (ctx.req.isExternalZip && fileInfo.zipInfo) {
        ctx.req.zipVirtualName = fileInfo.zipInfo.innerName
        ctx.req.cachedExternalZipInfo = fileInfo.zipInfo
      }
    }
    //  Check if it is a directory
    const realName = getRequestRealName(passwdInfo, fileName, fileInfo)
    const fpath = path.dirname(filePath) + '/' + realName
    console.log('@@@getFilePath', fpath)
    ctx.request.body.path = fpath
  }
  await next()
  if (passwdInfo && passwdInfo.encName) {
    // return showName
    const showName = getShowName(passwdInfo, ctx.body.data.name, fileInfo)
    ctx.body.data.name = showName
    if (fileInfo && fileInfo.externalZip && fileInfo.zipInfo) {
      ctx.body.data.type = getAListFileTypeByName(fileInfo.zipInfo.innerName)
    } else if (!ctx.req.isExternalZipCandidate) {
      ctx.body.data.type = getAListFileTypeByName(showName)
    }
  }
})

encNameRouter.all('/api/fs/rename', bodyparserMw, async (ctx, next) => {
  const { path: filePath, name } = ctx.request.body
  const { webdavConfig } = ctx.req
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, filePath)
  const reqBody = { path: filePath, name }
  ctx.req.reqBody = reqBody
  // reset content-length length
  delete ctx.req.headers['content-length']

  let fileInfo = await getCachedFileInfoByPath(filePath)
  if (fileInfo == null && passwdInfo && passwdInfo.encName) {
    // mabay a file
    const realName = convertRealName(passwdInfo.password, passwdInfo.encType, filePath)
    const realFilePath = path.dirname(filePath) + '/' + realName
    fileInfo = await getCachedFileInfoByPath(realFilePath)
  }
  if (passwdInfo && passwdInfo.encName && fileInfo && !fileInfo.is_dir) {
    // reset content-length length
    // you can custom Suffix
    const realName = fileInfo.externalZip
      ? fileInfo.name
      : convertRealName(passwdInfo.password, passwdInfo.encType, filePath)
    const fpath = path.dirname(filePath) + '/' + realName
    reqBody.path = fpath
    reqBody.name = getEncryptedFileName(passwdInfo, getExternalZipRenameTarget(fileInfo, name))
  }
  ctx.req.reqBody = reqBody
  console.log('@@@rename', reqBody)
  const respBody = await httpClient(ctx.req)
  ctx.body = respBody
})
// 替换字符，http://alist.com/p/enc123.txt?sign=12.. 替换 http://alist.com/p/realname.txt?sign=12..
const regexPath = /\/([^\\/]*?)(\?|$)/
const handleDownload = async (ctx, next) => {
  const request = ctx.req
  const { webdavConfig } = ctx.req
  let filePath = ctx.req.url.split('?')[0]
  // 如果是alist的话，那么必然有这个文件的size缓存（进过list就会被缓存起来）
  request.fileSize = 0
  // 这里需要处理掉/p 路径
  if (filePath.indexOf('/d/') === 0) {
    filePath = filePath.replace('/d/', '/')
  }
  // 这个不需要处理
  if (filePath.indexOf('/p/') === 0) {
    filePath = filePath.replace('/p/', '/')
  }
  const { passwdInfo } = pathFindPasswd(webdavConfig.passwdList, filePath)
  if (passwdInfo && passwdInfo.encName) {
    // reset content-length length
    delete ctx.req.headers['content-length']
    // Check whether the file name refers to an encrypted file or a directory
    const fileName = path.basename(filePath)
    const fileInfo = await getCachedFileInfoByPath(filePath)
    const realName = getRequestRealName(passwdInfo, fileName, fileInfo)
    // Replace the real-name before downloading
    ctx.req.url = ctx.req.url.replace(regexPath, `/${realName}$2`)
    ctx.req.urlAddr = ctx.req.urlAddr.replace(regexPath, `/${realName}$2`)
    logger.debug('@@download-fileName', ctx.req.url, fileName, realName)
    await next()
    return
  }
  await next()
}

encNameRouter.get(/^\/d\/*/, bodyparserMw, handleDownload)
encNameRouter.get(/\/p\/*/, bodyparserMw, handleDownload)

// restRouter.all(/\/enc-api\/*/, router.routes(), restRouter.allowedMethods())
export default encNameRouter
