import { pathToRegexp } from 'path-to-regexp'
import FlowEnc from './flowEnc'
import path from 'path'

import MixBase64 from './mixBase64'
import Crcn from './crc6-8'

const crc6 = new Crcn(6)
const origPrefix = 'orig_'
const zipEncType = 'zip'
const zipSuffix = '.zip'
const videoExts = new Set([
  '.mp4',
  '.m4v',
  '.webm',
  '.mkv',
  '.avi',
  '.mov',
  '.flv',
  '.wmv',
  '.ts',
  '.mpg',
  '.mpeg',
  '.3gp',
  '.m2ts',
])
const audioExts = new Set(['.mp3', '.m4a', '.aac', '.flac', '.wav', '.ogg', '.opus', '.wma'])
const imageExts = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico', '.heic', '.avif'])

function safeDecodeURIComponent(text: string) {
  try {
    return decodeURIComponent(text)
  } catch (e) {
    return text
  }
}

export function encodeZipStorageName(password: string, encType: string, plainName: string) {
  const decodedName = safeDecodeURIComponent(plainName || '')
  const ext = path.extname(decodedName)
  return encodeName(password, encType, decodedName) + ext + zipSuffix
}

export function decodeZipStorageName(password: string, encType: string, storageName: string) {
  if (encType !== zipEncType) {
    return null
  }
  const decodedStorageName = safeDecodeURIComponent(storageName || '')
  if (!decodedStorageName.toLocaleLowerCase().endsWith(zipSuffix)) {
    return null
  }
  const withoutZip = decodedStorageName.substring(0, decodedStorageName.length - zipSuffix.length)
  const visibleExt = path.extname(withoutZip)
  const cipherName = visibleExt ? withoutZip.substring(0, withoutZip.length - visibleExt.length) : withoutZip
  if (!cipherName) {
    return null
  }
  const showName = decodeName(password, encType, cipherName)
  if (!showName) {
    return null
  }
  const showExt = path.extname(showName)
  if (visibleExt && showExt && visibleExt.toLocaleLowerCase() !== showExt.toLocaleLowerCase()) {
    return null
  }
  return showName
}

// check file name, return real name
export function convertRealName(password: string, encType: string, pathText: string) {
  const fileName = path.basename(safeDecodeURIComponent(pathText))
  if (fileName.indexOf(origPrefix) === 0) {
    return fileName.replace(origPrefix, '')
  }
  if (encType === zipEncType) {
    if (decodeZipStorageName(password, encType, fileName)) {
      return fileName
    }
    return encodeZipStorageName(password, encType, fileName)
  }
  // try encode name, fileName don't need decodeURI，encodeUrl func can't encode that like '(' '!'  in nodejs
  const ext = path.extname(fileName)
  const encName = encodeName(password, encType, safeDecodeURIComponent(fileName))
  console.log('@@decodeURI(fileName)', safeDecodeURIComponent(fileName))
  return encName + ext
}

// if file name has encrypt, return show name
export function convertShowName(password: string, encType: string, pathText: string) {
  const fileName = path.basename(safeDecodeURIComponent(pathText))
  if (encType === zipEncType) {
    return decodeZipStorageName(password, encType, fileName) || fileName
  }
  const ext = path.extname(fileName)
  const encName = fileName.replace(ext, '')
  // encName don't need decodeURI
  let showName = decodeName(password, encType, encName)
  if (showName === null) {
    showName = origPrefix + fileName
  }
  return showName
}

export function inferAListType(fileName: string, fallbackType = 0) {
  const ext = path.extname(safeDecodeURIComponent(fileName || '')).toLocaleLowerCase()
  if (videoExts.has(ext)) {
    return 2
  }
  if (audioExts.has(ext)) {
    return 3
  }
  if (imageExts.has(ext)) {
    return 5
  }
  return fallbackType
}

// 判断是否为匹配的路径
export function pathExec(encPath: string[], url: string) {
  for (const filePath of encPath) {
    const result = pathToRegexp(new RegExp(filePath)).exec(url)
    if (result) {
      return result
    }
  }
  return null
}

export function encodeName(password: string, encType: string, plainName: string) {
  const passwdOutward = FlowEnc.getPassWdOutward(password, encType)
  //  randomStr
  const mix64 = new MixBase64(passwdOutward)
  let encodeName = mix64.encode(plainName)
  const crc6Bit = crc6.checksum(Buffer.from(encodeName + passwdOutward))
  const crc6Check = MixBase64.getSourceChar(crc6Bit)
  encodeName += crc6Check
  return encodeName
}

export function decodeName(password: string, encType: string, encodeName: string) {
  const crc6Check = encodeName.substring(encodeName.length - 1)
  const passwdOutward = FlowEnc.getPassWdOutward(password, encType)
  const mix64 = new MixBase64(passwdOutward)
  // start dec
  const subEncName = encodeName.substring(0, encodeName.length - 1)
  const crc6Bit = crc6.checksum(Buffer.from(subEncName + passwdOutward))
  // console.log(subEncName, MixBase64.getSourceChar(crc6Bit), crc6Check)
  if (MixBase64.getSourceChar(crc6Bit) !== crc6Check) {
    return null
  }
  // event pass crc6，it maybe decode error, like this name '68758PICxAd_1024-666 - 副本33.png'
  let decodeStr = null
  try {
    decodeStr = mix64.decode(subEncName).toString('utf8')
  } catch (e) {
    console.log('@@mix64 decode error', subEncName)
  }
  return decodeStr
}

export function encodeFolderName(password: string, encType: string, folderPasswd: string, folderEncType: string) {
  const passwdInfo = folderEncType + '_' + folderPasswd
  return encodeName(password, encType, passwdInfo)
}

export function decodeFolderName(password: string, encType: string, encodeName: string) {
  const arr = encodeName.split('_')
  if (arr.length < 2) {
    return false
  }
  const folderEncName = arr[arr.length - 1]
  const decodeStr = decodeName(password, encType, folderEncName)
  if (!decodeStr) {
    return decodeStr
  }
  const folderEncType = decodeStr.substring(0, decodeStr.indexOf('_'))
  const folderPasswd = decodeStr.substring(decodeStr.indexOf('_') + 1)
  return { folderEncType, folderPasswd }
}

// 检查
export function pathFindPasswd(passwdList: PasswdInfo[], url: string) {
  for (const passwdInfo of passwdList) {
    for (const filePath of passwdInfo.encPath) {
      const result = passwdInfo.enable ? pathToRegexp(new RegExp(filePath)).exec(url) : null
      if (result) {
        // check folder name is can decode
        // getPassInfo()
        const newPasswdInfo = Object.assign({}, passwdInfo)
        // url maybe a folder, need decode
        const folders = url.split('/')
        for (const folderName of folders) {
          const data = decodeFolderName(passwdInfo.password, passwdInfo.encType, decodeURIComponent(folderName))
          if (data) {
            newPasswdInfo.encType = data.folderEncType
            newPasswdInfo.password = data.folderPasswd
            return { passwdInfo: newPasswdInfo, pathInfo: result }
          }
        }
        return { passwdInfo, pathInfo: result }
      }
    }
  }
  return {}
}
