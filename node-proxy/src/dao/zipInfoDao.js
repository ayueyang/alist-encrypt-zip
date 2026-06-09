import crypto from 'crypto'
import levelDB from '@/utils/levelDB'

const zipInfoTable = 'zipInfoTable_'
const cacheTime = 60 * 60 * 24 * 30

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex')
}

function normalizePath(filePath = '') {
  try {
    return decodeURIComponent(String(filePath))
  } catch (e) {
    return String(filePath)
  }
}

function pickModified(fileInfo = {}) {
  return (
    fileInfo.modified ||
    fileInfo.updated ||
    fileInfo.modify_time ||
    fileInfo.modified_at ||
    fileInfo.updated_at ||
    fileInfo.last_modified ||
    ''
  )
}

export function zipInfoValidator(fileInfo = {}, fallbackSize = 0) {
  fileInfo = fileInfo || {}
  return {
    size: Number(fileInfo.size || fallbackSize || 0),
    modified: pickModified(fileInfo),
  }
}

export function zipInfoCacheKey({ realPath, passwdInfo }) {
  const keyData = {
    path: normalizePath(realPath),
    encType: passwdInfo && passwdInfo.encType,
    zipMode: (passwdInfo && passwdInfo.zipMode) || '',
    passwordHash: sha256(String((passwdInfo && passwdInfo.password) || '')).slice(0, 24),
  }
  return zipInfoTable + sha256(JSON.stringify(keyData))
}

export function serializeZipInfo(zipInfo) {
  if (!zipInfo) return null
  return {
    ...zipInfo,
    salt: zipInfo.salt ? Buffer.from(zipInfo.salt).toString('hex') : undefined,
    nonce: zipInfo.nonce ? Buffer.from(zipInfo.nonce).toString('hex') : undefined,
    meta: zipInfo.meta ? Buffer.from(zipInfo.meta).toString('hex') : undefined,
  }
}

export function deserializeZipInfo(zipInfo) {
  if (!zipInfo) return null
  return {
    ...zipInfo,
    salt: zipInfo.salt ? Buffer.from(zipInfo.salt, 'hex') : undefined,
    nonce: zipInfo.nonce ? Buffer.from(zipInfo.nonce, 'hex') : undefined,
    meta: zipInfo.meta ? Buffer.from(zipInfo.meta, 'hex') : undefined,
  }
}

function sameValidator(cached = {}, current = {}) {
  if (Number(cached.size || 0) !== Number(current.size || 0)) return false
  if (current.modified && cached.modified !== current.modified) return false
  return true
}

export async function getCachedZipInfo({ realPath, passwdInfo, validator }) {
  const cacheKey = zipInfoCacheKey({ realPath, passwdInfo })
  const cached = await levelDB.getValue(cacheKey)
  if (!cached || !sameValidator(cached.validator, validator)) {
    return null
  }
  return deserializeZipInfo(cached.zipInfo)
}

export async function cacheZipInfo({ realPath, passwdInfo, validator, zipInfo }) {
  const cacheKey = zipInfoCacheKey({ realPath, passwdInfo })
  await levelDB.setExpire(
    cacheKey,
    {
      table: zipInfoTable,
      realPath: normalizePath(realPath),
      validator,
      zipInfo: serializeZipInfo(zipInfo),
    },
    cacheTime
  )
}
