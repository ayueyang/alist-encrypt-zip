import levelDB from '@/utils/levelDB'
import crypto from 'crypto'

export const fileInfoTable = 'fileInfoTable_'

// 缓存多少分钟
const cacheTime = 60 * 24
const defaultFileInfoCacheSeconds = 60 * cacheTime
export const defaultZipInfoCacheDays = 30

export async function initFileTable() {}

export function isZipInfoCacheEnabled(passwdInfo = {}) {
  return !passwdInfo || passwdInfo.zipInfoCache !== false
}

export function getZipInfoCacheExpireSeconds(passwdInfo = {}) {
  const days = Number(passwdInfo && passwdInfo.zipInfoCacheDays)
  return (Number.isFinite(days) && days > 0 ? days : defaultZipInfoCacheDays) * 24 * 60 * 60
}

// 缓存文件信息
export async function cacheFileInfo(fileInfo, expireSeconds = null) {
  fileInfo.path = decodeURIComponent(fileInfo.path)
  const pathKey = fileInfoTable + fileInfo.path
  const cachedFileInfo = await levelDB.getValue(pathKey)
  if (
    cachedFileInfo &&
    cachedFileInfo.zipInfo &&
    !fileInfo.zipInfo &&
    Number(cachedFileInfo.size) === Number(fileInfo.size)
  ) {
    fileInfo.plainSize = cachedFileInfo.plainSize
    fileInfo.zipInfo = cachedFileInfo.zipInfo
    fileInfo.externalZip = cachedFileInfo.externalZip
    fileInfo.zipVirtualName = cachedFileInfo.zipVirtualName
  }
  if (
    cachedFileInfo &&
    cachedFileInfo.sevenZipAesCbcInfo &&
    !fileInfo.sevenZipAesCbcInfo &&
    Number(cachedFileInfo.size) === Number(fileInfo.size)
  ) {
    fileInfo.plainSize = cachedFileInfo.plainSize
    fileInfo.sevenZipAesCbcInfo = cachedFileInfo.sevenZipAesCbcInfo
    fileInfo.externalSevenZipAesCbc = cachedFileInfo.externalSevenZipAesCbc
    fileInfo.sevenZipAesCbcPasswordHash = cachedFileInfo.sevenZipAesCbcPasswordHash
    fileInfo.sevenZipAesCbcVirtualName = cachedFileInfo.sevenZipAesCbcVirtualName
    fileInfo.sevenZipAesCbcPackageName = cachedFileInfo.sevenZipAesCbcPackageName
    fileInfo.sevenZipAesCbcPackagePath = cachedFileInfo.sevenZipAesCbcPackagePath
  }
  fileInfo.table = fileInfoTable
  const customExpireSeconds = Number(expireSeconds)
  const finalExpireSeconds =
    Number.isFinite(customExpireSeconds) && customExpireSeconds > 0
      ? customExpireSeconds
      : fileInfo.zipInfo || fileInfo.sevenZipAesCbcInfo
        ? getZipInfoCacheExpireSeconds()
        : defaultFileInfoCacheSeconds
  await levelDB.setExpire(pathKey, fileInfo, finalExpireSeconds)
}

// 获取文件信息，偶尔要清理一下缓存
export async function getFileInfo(path) {
  const pathKey = decodeURIComponent(fileInfoTable + path)
  const value = await levelDB.getValue(pathKey)
  return value
}

// 获取文件信息
export async function getAllFileInfo() {
  const value = await levelDB.getValue({ table: fileInfoTable })
  return value
}
