import levelDB from '@/utils/levelDB'
import crypto from 'crypto'

export const fileInfoTable = 'fileInfoTable_'

// 缓存多少分钟
const cacheTime = 60 * 24

export async function initFileTable() {}

// 缓存文件信息
export async function cacheFileInfo(fileInfo, expireSeconds = 1000 * 60 * cacheTime) {
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
  fileInfo.table = fileInfoTable
  await levelDB.setExpire(pathKey, fileInfo, expireSeconds)
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
