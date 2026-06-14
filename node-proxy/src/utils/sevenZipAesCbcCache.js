import path from 'path'
import crypto from 'crypto'
import { cacheFileInfo, getFileInfo, getZipInfoCacheExpireSeconds, isZipInfoCacheEnabled } from '../dao/fileDao'
import levelDB from './levelDB'
import {
  buildSevenZipAesCbcInfo,
  getSevenZipAesCbcPackageName,
  isSevenZipAesCbcEncType,
  parseSevenZipAesCbcInfoFromRemote,
  serializeSevenZipAesCbcInfo,
} from './sevenZipAesCbc'

const NEGATIVE_CACHE_SECONDS = 10 * 60
const PROBE_CACHE_VERSION = 3
const PROBE_TABLE = 'sevenZipAesCbcProbe_'
const probeQueue = []
const pendingKeys = new Set()
let probing = false

function normalizePath(filePath = '') {
  return decodeURIComponent(filePath)
}

export function getSevenZipAesCbcUploadCachePaths(filePath = '') {
  const normalizedPath = normalizePath(filePath)
  const cachePaths = [normalizedPath]
  if (normalizedPath.indexOf('/dav/') === 0) {
    cachePaths.push(normalizedPath.substring(4))
  } else if (normalizedPath.indexOf('/') === 0) {
    cachePaths.push('/dav' + normalizedPath)
  }
  const result = []
  for (let i = 0; i < cachePaths.length; i++) {
    if (result.indexOf(cachePaths[i]) === -1) {
      result.push(cachePaths[i])
    }
  }
  return result
}

function normalizeSize(size) {
  return Number(size) || 0
}

function probeKey(filePath) {
  return PROBE_TABLE + normalizePath(filePath)
}

export function getSevenZipAesCbcPasswordHash(password) {
  if (password === undefined || password === null) return undefined
  return crypto.createHash('sha256').update(String(password)).digest('hex')
}

function isMatchedSevenZipAesCbcPassword(fileInfo, password) {
  const passwordHash = getSevenZipAesCbcPasswordHash(password)
  if (!passwordHash) return true
  return fileInfo && fileInfo.sevenZipAesCbcPasswordHash === passwordHash
}

export function isSevenZipAesCbcFileName(fileName = '') {
  return String(fileName || '').toLowerCase().endsWith('.7z')
}

export function isUsableSevenZipAesCbcInfoCache(fileInfo, size, password) {
  return !!(
    fileInfo &&
    fileInfo.sevenZipAesCbcInfo &&
    isSevenZipAesCbcEncType(fileInfo.sevenZipAesCbcInfo.encType) &&
    Number(fileInfo.size) === normalizeSize(size) &&
    isMatchedSevenZipAesCbcPassword(fileInfo, password)
  )
}

export function isUsableSevenZipAesCbcNegativeCache(probeInfo, size, password) {
  return !!(
    probeInfo &&
    probeInfo.version === PROBE_CACHE_VERSION &&
    probeInfo.notPlayable &&
    Number(probeInfo.size) === normalizeSize(size) &&
    isMatchedSevenZipAesCbcPassword(probeInfo, password)
  )
}

export async function getSevenZipAesCbcProbeCache(filePath, size, password, options = {}) {
  const cachedFileInfo = (await getFileInfo(filePath)) || (await getFileInfo(encodeURIComponent(filePath)))
  if (!options.ignoreInfoCache && isUsableSevenZipAesCbcInfoCache(cachedFileInfo, size, password)) {
    return { type: 'hit', fileInfo: cachedFileInfo }
  }
  const negativeProbe = await levelDB.getValue(probeKey(filePath))
  if (isUsableSevenZipAesCbcNegativeCache(negativeProbe, size, password)) {
    return { type: 'negative', probeInfo: negativeProbe, fileInfo: cachedFileInfo }
  }
  return { type: 'miss', fileInfo: cachedFileInfo }
}

export async function getSevenZipAesCbcCachedFileInfoByVirtualPath(filePath, password) {
  const normalizedPath = normalizePath(filePath)
  const cachedFileInfo = (await getFileInfo(normalizedPath)) || (await getFileInfo(encodeURIComponent(normalizedPath)))
  if (cachedFileInfo && cachedFileInfo.sevenZipAesCbcInfo && isMatchedSevenZipAesCbcPassword(cachedFileInfo, password)) {
    return cachedFileInfo
  }
  const packagePath = normalizePath(path.dirname(normalizedPath) + '/' + getSevenZipAesCbcPackageName(path.basename(normalizedPath)))
  if (packagePath === normalizedPath) return null
  const cachedPackageInfo =
    (await getFileInfo(packagePath)) || (await getFileInfo(encodeURIComponent(packagePath)))
  if (cachedPackageInfo && cachedPackageInfo.sevenZipAesCbcInfo && isMatchedSevenZipAesCbcPassword(cachedPackageInfo, password)) {
    return cachedPackageInfo
  }
  return null
}

export async function cacheExternalSevenZipAesCbcInfo(fileInfo, sevenZipAesCbcInfo, password) {
  const nextFileInfo = {
    ...fileInfo,
    path: normalizePath(fileInfo.path),
    name: fileInfo.name || path.basename(fileInfo.path),
    size: normalizeSize(fileInfo.size),
    plainSize: sevenZipAesCbcInfo.plainSize,
    sevenZipAesCbcInfo: serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo),
    externalSevenZipAesCbc: true,
    sevenZipAesCbcPasswordHash: getSevenZipAesCbcPasswordHash(password),
    sevenZipAesCbcVirtualName: sevenZipAesCbcInfo.innerName,
    sevenZipAesCbcPackageName: fileInfo.name || path.basename(fileInfo.path),
    sevenZipAesCbcPackagePath: normalizePath(fileInfo.path),
  }
  const passwdInfo = typeof password === 'object' ? password : null
  const cachePassword = passwdInfo ? passwdInfo.password : password
  nextFileInfo.sevenZipAesCbcPasswordHash = getSevenZipAesCbcPasswordHash(cachePassword)
  if (!isZipInfoCacheEnabled(passwdInfo)) return nextFileInfo
  const expireSeconds = getZipInfoCacheExpireSeconds(passwdInfo)
  await cacheFileInfo(nextFileInfo, expireSeconds)
  const virtualPath = normalizePath(path.dirname(nextFileInfo.path) + '/' + sevenZipAesCbcInfo.innerName)
  if (virtualPath !== nextFileInfo.path) {
    await cacheFileInfo({
      ...nextFileInfo,
      path: virtualPath,
      name: sevenZipAesCbcInfo.innerName,
      sevenZipAesCbcPackageName: nextFileInfo.sevenZipAesCbcPackageName,
      sevenZipAesCbcPackagePath: nextFileInfo.path,
    }, expireSeconds)
  }
  return nextFileInfo
}

export async function cacheGeneratedSevenZipAesCbcInfo({
  password,
  filePath,
  realName,
  originalName,
  plainSize,
  packageSize,
  iv,
  passwdInfo,
}) {
  if (!isZipInfoCacheEnabled(passwdInfo)) return null
  const sevenZipAesCbcInfo = buildSevenZipAesCbcInfo(plainSize, { originalName, iv })
  const expireSeconds = getZipInfoCacheExpireSeconds(passwdInfo)
  const nextFileInfo = {
    path: normalizePath(filePath),
    name: realName || path.basename(filePath),
    is_dir: false,
    size: normalizeSize(packageSize),
    plainSize: sevenZipAesCbcInfo.plainSize,
    sevenZipAesCbcInfo: serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo),
    externalSevenZipAesCbc: true,
    sevenZipAesCbcPasswordHash: getSevenZipAesCbcPasswordHash(password),
    sevenZipAesCbcVirtualName: sevenZipAesCbcInfo.innerName,
    sevenZipAesCbcPackageName: realName || path.basename(filePath),
    sevenZipAesCbcPackagePath: normalizePath(filePath),
  }
  await cacheFileInfo(nextFileInfo, expireSeconds)
  const virtualPath = normalizePath(path.dirname(nextFileInfo.path) + '/' + sevenZipAesCbcInfo.innerName)
  if (virtualPath !== nextFileInfo.path) {
    await cacheFileInfo({
      ...nextFileInfo,
      path: virtualPath,
      name: sevenZipAesCbcInfo.innerName,
      sevenZipAesCbcPackageName: nextFileInfo.sevenZipAesCbcPackageName,
      sevenZipAesCbcPackagePath: nextFileInfo.path,
    }, expireSeconds)
  }
  return nextFileInfo
}

export async function cacheExternalSevenZipAesCbcNegative(fileInfo, error, password) {
  await levelDB.setExpire(
    probeKey(fileInfo.path),
    {
      path: normalizePath(fileInfo.path),
      version: PROBE_CACHE_VERSION,
      size: normalizeSize(fileInfo.size),
      notPlayable: true,
      sevenZipAesCbcPasswordHash: getSevenZipAesCbcPasswordHash(password),
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
        const cached = await getSevenZipAesCbcProbeCache(job.fileInfo.path, job.fileInfo.size, job.password, {
          ignoreInfoCache: !isZipInfoCacheEnabled(job.passwdInfo),
        })
        if (cached.type === 'miss') {
          const sevenZipAesCbcInfo = await parseSevenZipAesCbcInfoFromRemote(
            job.urlAddr,
            job.headers,
            job.fileInfo.size,
            job.password
          )
          await cacheExternalSevenZipAesCbcInfo(job.fileInfo, sevenZipAesCbcInfo, job.passwdInfo || job.password)
        }
      } catch (e) {
        await cacheExternalSevenZipAesCbcNegative(job.fileInfo, e, job.password)
      } finally {
        pendingKeys.delete(key)
      }
    }
  } finally {
    probing = false
  }
}

export function enqueueExternalSevenZipAesCbcProbe({ fileInfo, urlAddr, headers, password, passwdInfo }) {
  if (!fileInfo || fileInfo.is_dir || !isSevenZipAesCbcFileName(fileInfo.name)) {
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
    password: password || (passwdInfo && passwdInfo.password),
    passwdInfo,
  })
  setTimeout(processQueue, 0)
  return true
}
