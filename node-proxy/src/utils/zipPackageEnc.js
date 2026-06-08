import crypto from 'crypto'
import fs from 'fs'
import http from 'http'
import https from 'node:https'
import path from 'path'
import { Transform } from 'stream'

export const ZIP_ENC_TYPE = 'zip'
export const ZIP_MODE_FAKE = 'fake'
export const ZIP_MODE_COMPATIBLE = 'compatible'
export const ZIP_MODE_WINZIP_AES = 'winzip-aes'

const INNER_FILENAME = 'payload.bin'
const CUSTOM_EXTRA_ID = 0x5a46 // "FZ" in little endian
const ZIP64_EXTRA_ID = 0x0001
const WINZIP_AES_EXTRA_ID = 0x9901
const MODE_FAKE_AES_CTR = 0
const MODE_COMPATIBLE_ZIPCRYPTO = 1
const MODE_WINZIP_AES = 2
const VERSION = 1
const SALT_SIZE = 16
const NONCE_SIZE = 16
const KEY_SIZE = 32
const PBKDF2_ITERATIONS = 100000
const WINZIP_AES_SALT_SIZE = 16
const WINZIP_AES_VERIFY_SIZE = 2
const WINZIP_AES_AUTH_SIZE = 10
const WINZIP_AES_KEY_SIZE = 32
const WINZIP_AES_STRENGTH = 3
const WINZIP_AES_VENDOR = Buffer.from('AE', 'ascii')
const WINZIP_AES_VERSION = 2
const WINZIP_AES_METHOD = 99
const WINZIP_AES_PBKDF2_ITERATIONS = 1000
const ZIP32_MAX = 0xffffffff
const ZIPCRYPTO_HEADER_SIZE = 12
const CHECKPOINT_LIMIT = 4000
const CHECKPOINT_MIN_INTERVAL = 1024 * 1024
const FIXED_DOS_TIME = 0x4800
const FIXED_DOS_DATE = 0x5a2a
const ZIP_FLAGS = 0x0001 | 0x0008
const STORE_METHOD = 0
const DEFAULT_META_KEY = Buffer.from('ZIPMETA1', 'ascii')

const MIME_MAP = {
  '.mp4': 'video/mp4',
  '.m4v': 'video/mp4',
  '.webm': 'video/webm',
  '.mkv': 'video/x-matroska',
  '.avi': 'video/x-msvideo',
  '.mov': 'video/quicktime',
  '.flv': 'video/x-flv',
  '.wmv': 'video/x-ms-wmv',
  '.ts': 'video/mp2t',
  '.mpg': 'video/mpeg',
  '.mpeg': 'video/mpeg',
  '.mp3': 'audio/mpeg',
  '.m4a': 'audio/mp4',
  '.aac': 'audio/aac',
  '.flac': 'audio/flac',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8',
  '.pdf': 'application/pdf',
}

const CRC_TABLE = (() => {
  const table = []
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[i] = c >>> 0
  }
  return table
})()

function crc32(buffer, previous = 0) {
  let crc = (previous ^ -1) >>> 0
  for (let i = 0; i < buffer.length; i++) {
    crc = CRC_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ -1) >>> 0
}

class ZipCrypto {
  constructor() {
    this.key0 = 0x12345678
    this.key1 = 0x23456789
    this.key2 = 0x34567890
  }

  initPassword(password) {
    const key = Buffer.from(String(password), 'utf8')
    for (const b of key) {
      this.updateKeys(b)
    }
  }

  updateKeys(byteValue) {
    this.key0 = (CRC_TABLE[(this.key0 ^ byteValue) & 0xff] ^ (this.key0 >>> 8)) >>> 0
    this.key1 = (Math.imul((this.key1 + (this.key0 & 0xff)) >>> 0, 134775813) + 1) >>> 0
    this.key2 = (CRC_TABLE[(this.key2 ^ (this.key1 >>> 24)) & 0xff] ^ (this.key2 >>> 8)) >>> 0
  }

  streamByte() {
    const temp = (this.key2 | 2) & 0xffff
    return (Math.imul(temp, temp ^ 1) >>> 8) & 0xff
  }

  encrypt(data) {
    const result = Buffer.alloc(data.length)
    for (let i = 0; i < data.length; i++) {
      const plain = data[i]
      result[i] = plain ^ this.streamByte()
      this.updateKeys(plain)
    }
    return result
  }

  decrypt(data) {
    const result = Buffer.alloc(data.length)
    for (let i = 0; i < data.length; i++) {
      const plain = data[i] ^ this.streamByte()
      result[i] = plain
      this.updateKeys(plain)
    }
    return result
  }

  getState() {
    return { key0: this.key0 >>> 0, key1: this.key1 >>> 0, key2: this.key2 >>> 0 }
  }

  setState(state) {
    this.key0 = state.key0 >>> 0
    this.key1 = state.key1 >>> 0
    this.key2 = state.key2 >>> 0
  }
}

function uint64Buffer(value) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64LE(BigInt(value), 0)
  return buffer
}

function readUInt64LE(buffer, offset) {
  const value = buffer.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('zip package is too large for javascript number precision')
  }
  return Number(value)
}

function isZip64Needed(plainSize, compressedSize = plainSize, centralOffset = 0, centralSize = 0) {
  return plainSize > ZIP32_MAX || compressedSize > ZIP32_MAX || centralOffset > ZIP32_MAX || centralSize > ZIP32_MAX
}

function normalizeName(name) {
  return path.basename(decodeURIComponent(name || INNER_FILENAME)) || INNER_FILENAME
}

function getInnerName(name) {
  const ext = path.extname(normalizeName(name)).toLowerCase()
  return `payload${ext || '.bin'}`
}

function normalizeZipMode(mode) {
  if (mode === ZIP_MODE_FAKE || mode === MODE_FAKE_AES_CTR) return ZIP_MODE_FAKE
  if (mode === ZIP_MODE_WINZIP_AES || mode === MODE_WINZIP_AES) return ZIP_MODE_WINZIP_AES
  return ZIP_MODE_COMPATIBLE
}

function modeNumber(zipMode) {
  const normalizedMode = normalizeZipMode(zipMode)
  if (normalizedMode === ZIP_MODE_FAKE) return MODE_FAKE_AES_CTR
  if (normalizedMode === ZIP_MODE_WINZIP_AES) return MODE_WINZIP_AES
  return MODE_COMPATIBLE_ZIPCRYPTO
}

function deriveOutwardPassword(password) {
  if (password.length === 32) {
    return password
  }
  return crypto.pbkdf2Sync(password, 'ZIP-AES-CTR', 1000, 16, 'sha256').toString('hex')
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_SIZE, 'sha256')
}

function deriveWinZipAesKeys(password, salt) {
  const material = crypto.pbkdf2Sync(
    Buffer.from(String(password), 'utf8'),
    salt,
    WINZIP_AES_PBKDF2_ITERATIONS,
    WINZIP_AES_KEY_SIZE * 2 + WINZIP_AES_VERIFY_SIZE,
    'sha1'
  )
  return {
    encKey: material.subarray(0, WINZIP_AES_KEY_SIZE),
    macKey: material.subarray(WINZIP_AES_KEY_SIZE, WINZIP_AES_KEY_SIZE * 2),
    verifier: material.subarray(WINZIP_AES_KEY_SIZE * 2),
  }
}

function incrementIV(iv, increment) {
  const MAX_UINT32 = 0xffffffff
  const incrementBig = Math.trunc(increment / MAX_UINT32)
  const incrementLittle = (increment % MAX_UINT32) - incrementBig
  let overflow = 0
  for (let idx = 0; idx < 4; ++idx) {
    let num = iv.readUInt32BE(12 - idx * 4)
    let inc = overflow
    if (idx === 0) inc += incrementLittle
    if (idx === 1) inc += incrementBig
    num += inc
    const numBig = Math.trunc(num / MAX_UINT32)
    const numLittle = (num % MAX_UINT32) - numBig
    overflow = numBig
    iv.writeUInt32BE(numLittle, 12 - idx * 4)
  }
}

function createCtrCipher(key, nonce, position) {
  const iv = Buffer.from(nonce)
  incrementIV(iv, Math.trunc(position / 16))
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv)
  const offset = position % 16
  if (offset) {
    cipher.update(Buffer.alloc(offset))
  }
  return cipher
}

function incrementLittleEndianCounter(counter) {
  for (let i = 0; i < counter.length; i++) {
    counter[i] = (counter[i] + 1) & 0xff
    if (counter[i] !== 0) break
  }
}

function createWinZipAesCtr(key, position = 0) {
  const blockIndex = Math.trunc(Number(position || 0) / 16)
  let offset = 16
  let initialOffset = Math.trunc(Number(position || 0) % 16)
  const counter = Buffer.alloc(16)
  counter.writeBigUInt64LE(BigInt(blockIndex + 1), 0)
  const ecb = crypto.createCipheriv('aes-256-ecb', key, null)
  ecb.setAutoPadding(false)
  let keystream = Buffer.alloc(0)

  function nextKeyByte() {
    if (offset >= keystream.length) {
      keystream = ecb.update(counter)
      incrementLittleEndianCounter(counter)
      offset = initialOffset
      initialOffset = 0
    }
    return keystream[offset++]
  }

  return {
    update(data) {
      const output = Buffer.alloc(data.length)
      for (let i = 0; i < data.length; i++) {
        output[i] = data[i] ^ nextKeyByte()
      }
      return output
    },
    final() {
      ecb.final()
      return Buffer.alloc(0)
    },
  }
}

function metaPlainBuffer(originalName, innerName, zipMode) {
  return Buffer.from(
    JSON.stringify({
      origName: normalizeName(originalName),
      innerName: normalizeName(innerName),
      zipMode: normalizeZipMode(zipMode),
    }),
    'utf8'
  )
}

function encryptedMetaLength(originalName, innerName, zipMode) {
  return 4 + 16 + 12 + 16 + metaPlainBuffer(originalName, innerName, zipMode).length
}

function buildEncryptedMeta(password, originalName, innerName, zipMode) {
  if (!password) {
    return Buffer.alloc(encryptedMetaLength(originalName, innerName, zipMode))
  }
  const plain = metaPlainBuffer(originalName, innerName, zipMode)
  const salt = crypto.randomBytes(16)
  const nonce = crypto.randomBytes(12)
  const key = crypto.pbkdf2Sync(String(password || ''), salt, 1000, 32, 'sha256')
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(DEFAULT_META_KEY)
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([Buffer.from([1, salt.length, nonce.length, tag.length]), salt, nonce, tag, ciphertext])
}

function decryptMeta(password, meta) {
  if (!meta || meta.length < 4 || meta[0] !== 1) return null
  const saltLen = meta[1]
  const nonceLen = meta[2]
  const tagLen = meta[3]
  const dataStart = 4 + saltLen + nonceLen + tagLen
  if (dataStart > meta.length) return null
  try {
    const salt = meta.subarray(4, 4 + saltLen)
    const nonce = meta.subarray(4 + saltLen, 4 + saltLen + nonceLen)
    const tag = meta.subarray(4 + saltLen + nonceLen, dataStart)
    const ciphertext = meta.subarray(dataStart)
    const key = crypto.pbkdf2Sync(String(password || ''), salt, 1000, 32, 'sha256')
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(DEFAULT_META_KEY)
    decipher.setAuthTag(tag)
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'))
  } catch (e) {
    return null
  }
}

function checkpointLayout(plainSize) {
  const interval =
    Math.max(
      CHECKPOINT_MIN_INTERVAL,
      (Math.trunc(Math.ceil(plainSize / CHECKPOINT_LIMIT) / CHECKPOINT_MIN_INTERVAL) + 1) * CHECKPOINT_MIN_INTERVAL
    ) || CHECKPOINT_MIN_INTERVAL
  const count = Math.min(CHECKPOINT_LIMIT, Math.trunc(plainSize / interval) + 1)
  return { interval, count }
}

function encodeCheckpoints(interval, checkpoints) {
  const body = Buffer.alloc(8 + checkpoints.length * 16)
  body.writeUInt32LE(interval >>> 0, 0)
  body.writeUInt32LE(checkpoints.length >>> 0, 4)
  checkpoints.forEach((checkpoint, index) => {
    const offset = 8 + index * 16
    body.writeUInt32LE(checkpoint.offset >>> 0, offset)
    body.writeUInt32LE(checkpoint.state.key0 >>> 0, offset + 4)
    body.writeUInt32LE(checkpoint.state.key1 >>> 0, offset + 8)
    body.writeUInt32LE(checkpoint.state.key2 >>> 0, offset + 12)
  })
  return body
}

function emptyCheckpoints(plainSize) {
  const { interval, count } = checkpointLayout(plainSize)
  const checkpoints = []
  for (let i = 0; i < count; i++) {
    checkpoints.push({ offset: i * interval, state: { key0: 0, key1: 0, key2: 0 } })
  }
  return encodeCheckpoints(interval, checkpoints)
}

function parseCheckpoints(data) {
  if (data.length < 8) return { checkpoints: [], cpInterval: 0 }
  const cpInterval = data.readUInt32LE(0)
  const count = data.readUInt32LE(4)
  const checkpoints = []
  for (let i = 0; i < count && 8 + i * 16 + 16 <= data.length; i++) {
    const offset = 8 + i * 16
    checkpoints.push({
      offset: data.readUInt32LE(offset),
      state: {
        key0: data.readUInt32LE(offset + 4),
        key1: data.readUInt32LE(offset + 8),
        key2: data.readUInt32LE(offset + 12),
      },
    })
  }
  return { checkpoints, cpInterval }
}

function buildCustomExtra({ zipMode, salt, nonce, meta = Buffer.alloc(0), checkpoints = Buffer.alloc(0) }) {
  const normalizedMode = normalizeZipMode(zipMode)
  const bodyParts = [
    Buffer.alloc(6),
    Buffer.isBuffer(meta) ? meta : Buffer.from(meta),
  ]
  bodyParts[0].writeUInt16LE(VERSION, 0)
  bodyParts[0].writeUInt16LE(modeNumber(normalizedMode), 2)
  bodyParts[0].writeUInt16LE(bodyParts[1].length, 4)
  if (normalizedMode === ZIP_MODE_FAKE) {
    bodyParts.push(salt, nonce)
  } else if (normalizedMode === ZIP_MODE_WINZIP_AES) {
    bodyParts.push(Buffer.isBuffer(salt) ? salt : Buffer.alloc(WINZIP_AES_SALT_SIZE))
  } else {
    bodyParts.push(checkpoints)
  }

  const body = Buffer.concat(bodyParts)
  const field = Buffer.alloc(4 + body.length)
  field.writeUInt16LE(CUSTOM_EXTRA_ID, 0)
  field.writeUInt16LE(body.length, 2)
  body.copy(field, 4)
  return field
}

function buildWinZipAesExtra() {
  const body = Buffer.alloc(7)
  body.writeUInt16LE(WINZIP_AES_VERSION, 0)
  WINZIP_AES_VENDOR.copy(body, 2)
  body.writeUInt8(WINZIP_AES_STRENGTH, 4)
  body.writeUInt16LE(STORE_METHOD, 5)
  const field = Buffer.alloc(4 + body.length)
  field.writeUInt16LE(WINZIP_AES_EXTRA_ID, 0)
  field.writeUInt16LE(body.length, 2)
  body.copy(field, 4)
  return field
}

function parseWinZipAesExtra(extra) {
  const field = parseExtraFields(extra).find((item) => item.id === WINZIP_AES_EXTRA_ID)
  if (!field || field.data.length !== 7) return null
  return {
    version: field.data.readUInt16LE(0),
    vendor: field.data.subarray(2, 4).toString('ascii'),
    strength: field.data.readUInt8(4),
    actualMethod: field.data.readUInt16LE(5),
  }
}

function buildZip64Extra(values) {
  const parts = []
  if (values.uncompressedSize !== undefined) parts.push(uint64Buffer(values.uncompressedSize))
  if (values.compressedSize !== undefined) parts.push(uint64Buffer(values.compressedSize))
  if (values.localHeaderOffset !== undefined) parts.push(uint64Buffer(values.localHeaderOffset))
  const body = Buffer.concat(parts)
  const field = Buffer.alloc(4 + body.length)
  field.writeUInt16LE(ZIP64_EXTRA_ID, 0)
  field.writeUInt16LE(body.length, 2)
  body.copy(field, 4)
  return field
}

function parseExtraFields(extra) {
  const fields = []
  let offset = 0
  while (offset + 4 <= extra.length) {
    const id = extra.readUInt16LE(offset)
    const size = extra.readUInt16LE(offset + 2)
    const dataStart = offset + 4
    const dataEnd = dataStart + size
    if (dataEnd > extra.length) break
    fields.push({ id, data: extra.subarray(dataStart, dataEnd) })
    offset = dataEnd
  }
  return fields
}

function parseCustomBody(data, raw = false) {
  if (raw) {
    const mode = data.readUInt16LE(2)
    const metaLen = data.readUInt16LE(4)
    const payloadStart = 6 + metaLen
    const payload = data.subarray(payloadStart)
    if (mode === MODE_FAKE_AES_CTR && payload.length >= SALT_SIZE + NONCE_SIZE) {
      return {
        version: 0,
        mode,
        zipMode: ZIP_MODE_FAKE,
        origName: data.subarray(6, 6 + metaLen).toString('utf8') || null,
        salt: payload.subarray(0, SALT_SIZE),
        nonce: payload.subarray(SALT_SIZE, SALT_SIZE + NONCE_SIZE),
        checkpoints: [],
      }
    }
    if (mode === MODE_COMPATIBLE_ZIPCRYPTO && payload.length >= 8) {
      return {
        version: 0,
        mode,
        zipMode: ZIP_MODE_COMPATIBLE,
        origName: data.subarray(6, 6 + metaLen).toString('utf8') || null,
        ...parseCheckpoints(payload),
      }
    }
    if (mode === MODE_WINZIP_AES && payload.length >= WINZIP_AES_SALT_SIZE) {
      return {
        version: 0,
        mode,
        zipMode: ZIP_MODE_WINZIP_AES,
        origName: data.subarray(6, 6 + metaLen).toString('utf8') || null,
        salt: payload.subarray(0, WINZIP_AES_SALT_SIZE),
        checkpoints: [],
      }
    }
    return null
  }

  if (data.length < 6) return null
  const version = data.readUInt16LE(0)
  const mode = data.readUInt16LE(2)
  const metaLen = data.readUInt16LE(4)
  if (version !== VERSION || data.length < 6 + metaLen) return null
  const meta = data.subarray(6, 6 + metaLen)
  const payload = data.subarray(6 + metaLen)
  if (mode === MODE_FAKE_AES_CTR && payload.length >= SALT_SIZE + NONCE_SIZE) {
    return {
      version,
      mode,
      zipMode: ZIP_MODE_FAKE,
      meta,
      origName: meta.length ? meta.toString('utf8') : null,
      salt: payload.subarray(0, SALT_SIZE),
      nonce: payload.subarray(SALT_SIZE, SALT_SIZE + NONCE_SIZE),
      checkpoints: [],
    }
  }
  if (mode === MODE_COMPATIBLE_ZIPCRYPTO) {
    return {
      version,
      mode,
      zipMode: ZIP_MODE_COMPATIBLE,
      meta,
      origName: meta.length ? meta.toString('utf8') : null,
      ...parseCheckpoints(payload),
    }
  }
  if (mode === MODE_WINZIP_AES && payload.length >= WINZIP_AES_SALT_SIZE) {
    return {
      version,
      mode,
      zipMode: ZIP_MODE_WINZIP_AES,
      meta,
      origName: null,
      salt: payload.subarray(0, WINZIP_AES_SALT_SIZE),
      checkpoints: [],
    }
  }
  return null
}

function parseCustomExtra(extra) {
  for (const field of parseExtraFields(extra)) {
    if (field.id !== CUSTOM_EXTRA_ID) continue
    const parsed = parseCustomBody(field.data)
    if (parsed) return parsed
  }

  // Compatibility with the Python prototype, whose extra data starts with raw "FZ".
  if (extra.length >= 6 && extra.subarray(0, 2).toString('ascii') === 'FZ') {
    const parsed = parseCustomBody(extra, true)
    if (parsed) return parsed
  }

  throw new Error('zip package extra field is not recognized')
}

function parseZip64Sizes(extra, need) {
  const result = {}
  const field = parseExtraFields(extra).find((item) => item.id === ZIP64_EXTRA_ID)
  if (!field) return result

  let offset = 0
  if (need.uncompressedSize && offset + 8 <= field.data.length) {
    result.uncompressedSize = readUInt64LE(field.data, offset)
    offset += 8
  }
  if (need.compressedSize && offset + 8 <= field.data.length) {
    result.compressedSize = readUInt64LE(field.data, offset)
    offset += 8
  }
  if (need.localHeaderOffset && offset + 8 <= field.data.length) {
    result.localHeaderOffset = readUInt64LE(field.data, offset)
  }
  return result
}

function buildLocalHeader({ plainSize, compressedSize, innerName, customExtra, method = STORE_METHOD, crc = 0, flags = ZIP_FLAGS }) {
  const fileName = Buffer.from(innerName || INNER_FILENAME, 'utf8')
  const zip64 = isZip64Needed(plainSize, compressedSize)
  const extra = zip64
    ? Buffer.concat([customExtra, buildZip64Extra({ uncompressedSize: plainSize, compressedSize })])
    : customExtra
  const header = Buffer.alloc(30)
  header.writeUInt32LE(0x04034b50, 0)
  header.writeUInt16LE(zip64 ? 45 : 20, 4)
  header.writeUInt16LE(flags, 6)
  header.writeUInt16LE(method, 8)
  header.writeUInt16LE(FIXED_DOS_TIME, 10)
  header.writeUInt16LE(FIXED_DOS_DATE, 12)
  header.writeUInt32LE(crc >>> 0, 14)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : 0, 18)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : 0, 22)
  header.writeUInt16LE(fileName.length, 26)
  header.writeUInt16LE(extra.length, 28)
  return Buffer.concat([header, fileName, extra])
}

function buildDataDescriptor({ crc, plainSize, compressedSize }) {
  const zip64 = isZip64Needed(plainSize, compressedSize)
  const descriptor = Buffer.alloc(zip64 ? 24 : 16)
  descriptor.writeUInt32LE(0x08074b50, 0)
  descriptor.writeUInt32LE(crc >>> 0, 4)
  if (zip64) {
    descriptor.writeBigUInt64LE(BigInt(compressedSize), 8)
    descriptor.writeBigUInt64LE(BigInt(plainSize), 16)
  } else {
    descriptor.writeUInt32LE(compressedSize >>> 0, 8)
    descriptor.writeUInt32LE(plainSize >>> 0, 12)
  }
  return descriptor
}

function buildCentralDirectory({ crc, plainSize, compressedSize, innerName, customExtra, localHeaderOffset, centralOffset, method = STORE_METHOD, flags = ZIP_FLAGS }) {
  const fileName = Buffer.from(innerName || INNER_FILENAME, 'utf8')
  const zip64 = isZip64Needed(plainSize, compressedSize, localHeaderOffset, centralOffset)
  const extra = zip64
    ? Buffer.concat([
        customExtra,
        buildZip64Extra({
          uncompressedSize: plainSize,
          compressedSize,
          localHeaderOffset,
        }),
      ])
    : customExtra
  const header = Buffer.alloc(46)
  header.writeUInt32LE(0x02014b50, 0)
  header.writeUInt16LE(zip64 ? 45 : 20, 4)
  header.writeUInt16LE(zip64 ? 45 : 20, 6)
  header.writeUInt16LE(flags, 8)
  header.writeUInt16LE(method, 10)
  header.writeUInt16LE(FIXED_DOS_TIME, 12)
  header.writeUInt16LE(FIXED_DOS_DATE, 14)
  header.writeUInt32LE(crc >>> 0, 16)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : compressedSize, 20)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : plainSize, 24)
  header.writeUInt16LE(fileName.length, 28)
  header.writeUInt16LE(extra.length, 30)
  header.writeUInt16LE(0, 32)
  header.writeUInt16LE(0, 34)
  header.writeUInt16LE(0, 36)
  header.writeUInt32LE(0, 38)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : localHeaderOffset, 42)
  return Buffer.concat([header, fileName, extra])
}

function buildEndRecords({ centralOffset, centralSize, zip64 }) {
  const records = []
  if (zip64) {
    const zip64EocdOffset = centralOffset + centralSize
    const zip64Eocd = Buffer.alloc(56)
    zip64Eocd.writeUInt32LE(0x06064b50, 0)
    zip64Eocd.writeBigUInt64LE(BigInt(44), 4)
    zip64Eocd.writeUInt16LE(45, 12)
    zip64Eocd.writeUInt16LE(45, 14)
    zip64Eocd.writeUInt32LE(0, 16)
    zip64Eocd.writeUInt32LE(0, 20)
    zip64Eocd.writeBigUInt64LE(BigInt(1), 24)
    zip64Eocd.writeBigUInt64LE(BigInt(1), 32)
    zip64Eocd.writeBigUInt64LE(BigInt(centralSize), 40)
    zip64Eocd.writeBigUInt64LE(BigInt(centralOffset), 48)
    records.push(zip64Eocd)

    const locator = Buffer.alloc(20)
    locator.writeUInt32LE(0x07064b50, 0)
    locator.writeUInt32LE(0, 4)
    locator.writeBigUInt64LE(BigInt(zip64EocdOffset), 8)
    locator.writeUInt32LE(1, 16)
    records.push(locator)
  }

  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(zip64 ? 0xffff : 1, 8)
  eocd.writeUInt16LE(zip64 ? 0xffff : 1, 10)
  eocd.writeUInt32LE(zip64 ? ZIP32_MAX : centralSize, 12)
  eocd.writeUInt32LE(zip64 ? ZIP32_MAX : centralOffset, 16)
  eocd.writeUInt16LE(0, 20)
  records.push(eocd)
  return Buffer.concat(records)
}

function buildTail({ crc, plainSize, compressedSize, innerName, customExtra, headerSize, method = STORE_METHOD, flags = ZIP_FLAGS }) {
  const descriptor = buildDataDescriptor({ crc, plainSize, compressedSize })
  const centralOffset = headerSize + compressedSize + descriptor.length
  const central = buildCentralDirectory({
    crc,
    plainSize,
    compressedSize,
    innerName,
    customExtra,
    localHeaderOffset: 0,
    centralOffset,
    method,
    flags,
  })
  const zip64 = isZip64Needed(plainSize, compressedSize, centralOffset, central.length)
  const endRecords = buildEndRecords({ centralOffset, centralSize: central.length, zip64 })
  return Buffer.concat([descriptor, central, endRecords])
}

function buildPackageLayout({ plainSize, originalName = INNER_FILENAME, innerName, zipMode = ZIP_MODE_COMPATIBLE, salt, nonce, password = '' }) {
  const normalizedMode = normalizeZipMode(zipMode)
  const zipInnerName = innerName || getInnerName(originalName)
  const compressedSize =
    plainSize +
    (normalizedMode === ZIP_MODE_COMPATIBLE ? ZIPCRYPTO_HEADER_SIZE : 0) +
    (normalizedMode === ZIP_MODE_WINZIP_AES ? WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE + WINZIP_AES_AUTH_SIZE : 0)
  const method = normalizedMode === ZIP_MODE_WINZIP_AES ? WINZIP_AES_METHOD : STORE_METHOD
  const winZipAesExtra = normalizedMode === ZIP_MODE_WINZIP_AES ? buildWinZipAesExtra() : Buffer.alloc(0)
  const meta = normalizedMode === ZIP_MODE_WINZIP_AES ? buildEncryptedMeta(password, originalName, zipInnerName, normalizedMode) : Buffer.alloc(0)
  const localExtra = buildCustomExtra({
    zipMode: normalizedMode,
    salt: salt || Buffer.alloc(SALT_SIZE),
    nonce: nonce || Buffer.alloc(NONCE_SIZE),
    meta,
    checkpoints: normalizedMode === ZIP_MODE_COMPATIBLE ? Buffer.alloc(0) : undefined,
  })
  const centralExtra = buildCustomExtra({
    zipMode: normalizedMode,
    salt: salt || Buffer.alloc(SALT_SIZE),
    nonce: nonce || Buffer.alloc(NONCE_SIZE),
    meta,
    checkpoints: normalizedMode === ZIP_MODE_COMPATIBLE ? emptyCheckpoints(plainSize) : undefined,
  })
  const header = buildLocalHeader({
    plainSize,
    compressedSize,
    innerName: zipInnerName,
    customExtra: Buffer.concat([localExtra, winZipAesExtra]),
    method,
  })
  const tail = buildTail({
    crc: 0,
    plainSize,
    compressedSize,
    innerName: zipInnerName,
    customExtra: Buffer.concat([centralExtra, winZipAesExtra]),
    headerSize: header.length,
    method,
  })
  return {
    zipMode: normalizedMode,
    headerSize: header.length,
    compressedSize,
    dataHeaderSize:
      normalizedMode === ZIP_MODE_COMPATIBLE
        ? ZIPCRYPTO_HEADER_SIZE
        : normalizedMode === ZIP_MODE_WINZIP_AES
          ? WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE
          : 0,
    authSize: normalizedMode === ZIP_MODE_WINZIP_AES ? WINZIP_AES_AUTH_SIZE : 0,
    packageSize: header.length + compressedSize + tail.length,
    innerName: zipInnerName,
  }
}

function parseRange(rangeHeader, totalSize) {
  if (!rangeHeader) {
    return { hasRange: false, start: 0, end: Math.max(0, totalSize - 1) }
  }
  const rangeSpec = rangeHeader.replace(/bytes=/i, '').trim()
  const [startText, endText] = rangeSpec.split('-')
  let start
  let end
  if (!startText && endText) {
    const suffixLength = Number(endText)
    start = Math.max(0, totalSize - suffixLength)
    end = totalSize - 1
  } else {
    start = Number(startText || 0)
    end = endText ? Number(endText) : totalSize - 1
  }
  if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start >= totalSize || end < start) {
    throw new Error('invalid range request')
  }
  return { hasRange: true, start, end: Math.min(end, totalSize - 1) }
}

function sanitizeForwardHeaders(headers = {}) {
  const result = { ...headers }
  delete result.host
  delete result.range
  delete result['content-length']
  delete result['content-range']
  delete result['transfer-encoding']
  delete result['accept-encoding']
  return result
}

function requestBuffer(urlAddr, options, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(urlAddr)
    const httpRequest = urlObj.protocol === 'https:' ? https : http
    const req = httpRequest.request(
      urlObj,
      {
        ...options,
        rejectUnauthorized: false,
      },
      (resp) => {
        const location = resp.headers.location
        if (resp.statusCode >= 300 && resp.statusCode < 400 && location && redirectCount < 5) {
          resp.resume()
          const nextUrl = new URL(location, urlObj).toString()
          const nextOptions = { ...options, headers: { ...(options.headers || {}) } }
          delete nextOptions.headers.host
          delete nextOptions.headers.authorization
          delete nextOptions.headers.referer
          requestBuffer(nextUrl, nextOptions, redirectCount + 1).then(resolve).catch(reject)
          return
        }
        const chunks = []
        resp.on('data', (chunk) => chunks.push(chunk))
        resp.on('end', () => resolve({ statusCode: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks), url: urlAddr }))
      }
    )
    req.on('error', reject)
    req.end()
  })
}

async function getRemoteSize(urlAddr, headers, candidateSize = 0) {
  const cleanHeaders = sanitizeForwardHeaders(headers)
  try {
    const head = await requestBuffer(urlAddr, { method: 'HEAD', headers: cleanHeaders })
    const contentLength = Number(head.headers['content-length'])
    if (head.statusCode >= 200 && head.statusCode < 300 && Number.isFinite(contentLength) && contentLength > 0) {
      return contentLength
    }
  } catch (e) {}

  try {
    const resp = await requestBuffer(urlAddr, {
      method: 'GET',
      headers: { ...cleanHeaders, Range: 'bytes=0-0' },
    })
    const contentRange = resp.headers['content-range'] || ''
    const total = Number(String(contentRange).split('/')[1])
    if (resp.statusCode === 206 && Number.isFinite(total) && total > 0) {
      return total
    }
    const contentLength = Number(resp.headers['content-length'])
    if (resp.statusCode === 200 && Number.isFinite(contentLength) && contentLength > 0) {
      return contentLength
    }
  } catch (e) {}

  if (candidateSize > 0) return candidateSize
  throw new Error('unable to detect remote zip package size')
}

async function readRemoteRange(urlAddr, headers, start, length) {
  const end = start + length - 1
  const cleanHeaders = sanitizeForwardHeaders(headers)
  const resp = await requestBuffer(urlAddr, {
    method: 'GET',
    headers: { ...cleanHeaders, Range: `bytes=${start}-${end}` },
  })
  if (resp.statusCode === 206) {
    return resp.body
  }
  if (resp.statusCode === 200) {
    return resp.body.subarray(start, start + length)
  }
  throw new Error(`remote range request failed: ${resp.statusCode}`)
}

async function parseEocd(tail, tailStart, readRange) {
  const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06])
  const pos = tail.lastIndexOf(eocdSig)
  if (pos < 0 || pos + 22 > tail.length) {
    throw new Error('zip package EOCD not found')
  }
  const eocd = tail.subarray(pos, pos + 22)
  let centralSize = eocd.readUInt32LE(12)
  let centralOffset = eocd.readUInt32LE(16)
  const needsZip64 = centralSize === ZIP32_MAX || centralOffset === ZIP32_MAX || eocd.readUInt16LE(8) === 0xffff

  if (!needsZip64) {
    return { centralOffset, centralSize }
  }

  const locatorSig = Buffer.from([0x50, 0x4b, 0x06, 0x07])
  const locatorPos = tail.lastIndexOf(locatorSig, pos)
  if (locatorPos < 0 || locatorPos + 20 > tail.length) {
    throw new Error('zip64 locator not found')
  }
  const zip64EocdOffset = readUInt64LE(tail, locatorPos + 8)
  let zip64Eocd
  const offsetInTail = zip64EocdOffset - tailStart
  if (offsetInTail >= 0 && offsetInTail + 56 <= tail.length) {
    zip64Eocd = tail.subarray(offsetInTail, offsetInTail + 56)
  } else {
    zip64Eocd = await readRange(zip64EocdOffset, 56)
  }
  if (zip64Eocd.readUInt32LE(0) !== 0x06064b50) {
    throw new Error('zip64 EOCD is invalid')
  }
  centralSize = readUInt64LE(zip64Eocd, 40)
  centralOffset = readUInt64LE(zip64Eocd, 48)
  return { centralOffset, centralSize }
}

function parseLocalHeaderBytes(fixed, rest) {
  const compressedSize32 = fixed.readUInt32LE(18)
  const uncompressedSize32 = fixed.readUInt32LE(22)
  const nameLen = fixed.readUInt16LE(26)
  const extraLen = fixed.readUInt16LE(28)
  const name = rest.subarray(0, nameLen).toString('utf8')
  const extra = rest.subarray(nameLen, nameLen + extraLen)
  const zip64 = parseZip64Sizes(extra, {
    uncompressedSize: uncompressedSize32 === ZIP32_MAX,
    compressedSize: compressedSize32 === ZIP32_MAX,
  })
  return {
    compressedSize: zip64.compressedSize ?? compressedSize32,
    uncompressedSize: zip64.uncompressedSize ?? uncompressedSize32,
    name,
    extra,
    headerSize: 30 + nameLen + extraLen,
  }
}

async function parseCentralDirectory(readRange, centralOffset) {
  const fixed = await readRange(centralOffset, 46)
  if (fixed.length < 46 || fixed.readUInt32LE(0) !== 0x02014b50) {
    throw new Error('central directory header is invalid')
  }
  const compressedSize32 = fixed.readUInt32LE(20)
  const uncompressedSize32 = fixed.readUInt32LE(24)
  const nameLen = fixed.readUInt16LE(28)
  const extraLen = fixed.readUInt16LE(30)
  const commentLen = fixed.readUInt16LE(32)
  const localHeaderOffset32 = fixed.readUInt32LE(42)
  const rest = await readRange(centralOffset + 46, nameLen + extraLen + commentLen)
  const name = rest.subarray(0, nameLen).toString('utf8')
  const extra = rest.subarray(nameLen, nameLen + extraLen)

  const zip64 = parseZip64Sizes(extra, {
    uncompressedSize: uncompressedSize32 === ZIP32_MAX,
    compressedSize: compressedSize32 === ZIP32_MAX,
    localHeaderOffset: localHeaderOffset32 === ZIP32_MAX,
  })
  return {
    compressedSize: zip64.compressedSize ?? compressedSize32,
    uncompressedSize: zip64.uncompressedSize ?? uncompressedSize32,
    localHeaderOffset: zip64.localHeaderOffset ?? localHeaderOffset32,
    name,
    extra,
  }
}

function findCompatibleCheckpoint(zipInfo, position) {
  let checkpoint = zipInfo.checkpoints && zipInfo.checkpoints[0]
  for (const item of zipInfo.checkpoints || []) {
    if (item.offset <= position) {
      checkpoint = item
    } else {
      break
    }
  }
  if (!checkpoint) {
    throw new Error('zip compatible checkpoint not found')
  }
  return checkpoint
}

export async function parseZipInfoFromReader(readRange, totalSize, options = {}) {
  const fixed = await readRange(0, 30)
  if (fixed.length < 30 || fixed.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('not a zip package encrypted file')
  }
  const flags = fixed.readUInt16LE(6)
  if ((flags & 1) === 0) {
    throw new Error('zip package is not marked encrypted')
  }
  const nameLen = fixed.readUInt16LE(26)
  const extraLen = fixed.readUInt16LE(28)
  const localRest = await readRange(30, nameLen + extraLen)
  const local = parseLocalHeaderBytes(fixed, localRest)

  const tailSize = Math.min(65536 + 128, totalSize)
  const tailStart = Math.max(0, totalSize - tailSize)
  const tail = await readRange(tailStart, totalSize - tailStart)
  const { centralOffset } = await parseEocd(tail, tailStart, readRange)
  const central = await parseCentralDirectory(readRange, centralOffset)
  const custom = parseCustomExtra(central.extra.length ? central.extra : local.extra)
  const customMeta = custom.meta && custom.meta.length ? decryptMeta(options.password, custom.meta) : null
  const winZipAes = parseWinZipAesExtra(central.extra.length ? central.extra : local.extra)
  const zipMode = winZipAes ? ZIP_MODE_WINZIP_AES : normalizeZipMode(custom.zipMode)
  const plainSize = central.uncompressedSize
  const compressedSize = central.compressedSize
  const dataHeaderSize =
    zipMode === ZIP_MODE_COMPATIBLE
      ? ZIPCRYPTO_HEADER_SIZE
      : zipMode === ZIP_MODE_WINZIP_AES
        ? WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE
        : 0
  const authSize = zipMode === ZIP_MODE_WINZIP_AES ? WINZIP_AES_AUTH_SIZE : 0

  return {
    encType: ZIP_ENC_TYPE,
    zipMode,
    version: custom.version,
    mode: custom.mode,
    origName: customMeta?.origName || custom.origName || null,
    innerName: customMeta?.innerName || central.name || local.name || INNER_FILENAME,
    salt: custom.salt,
    nonce: custom.nonce,
    meta: custom.meta,
    metaInfo: customMeta,
    winZipAes,
    checkpoints: custom.checkpoints || [],
    cpInterval: custom.cpInterval || 0,
    headerSize: local.headerSize,
    encryptedHeaderOffset: local.headerSize,
    payloadOffset: local.headerSize + dataHeaderSize,
    payloadSize: plainSize,
    authTagOffset: local.headerSize + compressedSize - authSize,
    authSize,
    plainSize,
    compressedSize,
    totalSize,
  }
}

export async function parseZipInfoFromFile(filePath, options = {}) {
  const stat = await fs.promises.stat(filePath)
  const handle = await fs.promises.open(filePath, 'r')
  try {
    const readRange = async (start, length) => {
      const buffer = Buffer.alloc(length)
      const result = await handle.read(buffer, 0, length, start)
      return buffer.subarray(0, result.bytesRead)
    }
    return await parseZipInfoFromReader(readRange, stat.size, options)
  } finally {
    await handle.close()
  }
}

export async function parseZipInfoFromRemote(urlAddr, headers = {}, candidateSize = 0, options = {}) {
  const totalSize = await getRemoteSize(urlAddr, headers, Number(candidateSize) || 0)
  const readRange = (start, length) => readRemoteRange(urlAddr, headers, start, length)
  return await parseZipInfoFromReader(readRange, totalSize, options)
}

export function isZipEncType(encType) {
  return encType === ZIP_ENC_TYPE
}

export function getMimeByName(name = '') {
  let fileName = String(name).split('?')[0]
  if (fileName.toLowerCase().endsWith('.zip')) {
    fileName = fileName.slice(0, -4)
  }
  const ext = path.extname(fileName).toLowerCase()
  return MIME_MAP[ext] || 'application/octet-stream'
}

export function prepareZipDownloadRequest(request, zipInfo, clientRangeHeader) {
  const plainRange = parseRange(clientRangeHeader, zipInfo.plainSize)
  request.zipInfo = zipInfo
  request.zipPlainRange = plainRange
  delete request.headers['accept-encoding']

  if (zipInfo.zipMode === ZIP_MODE_COMPATIBLE) {
    const checkpoint = findCompatibleCheckpoint(zipInfo, plainRange.start)
    request.zipCipherStart = checkpoint.offset
    request.zipSkipBytes = plainRange.start - checkpoint.offset
    request.zipCryptoState = checkpoint.state
    if (request.method.toLocaleUpperCase() !== 'HEAD') {
      const start = zipInfo.payloadOffset + checkpoint.offset
      const end = zipInfo.payloadOffset + plainRange.end
      request.zipPackageRange = { start, end }
      request.headers.range = `bytes=${start}-${end}`
    }
    return plainRange
  }

  request.zipCipherStart = plainRange.start
  request.zipSkipBytes = 0
  if (request.method.toLocaleUpperCase() !== 'HEAD') {
    const start = zipInfo.payloadOffset + plainRange.start
    const end = zipInfo.payloadOffset + plainRange.end
    request.zipPackageRange = { start, end }
    request.headers.range = `bytes=${start}-${end}`
  }
  return plainRange
}

export function applyZipResponseHeaders(response, request) {
  const { zipInfo, zipPlainRange } = request
  if (!zipInfo || !zipPlainRange) return
  if (response.statusCode >= 300 && response.statusCode < 400) return

  if (zipPlainRange.hasRange) {
    response.statusCode = 206
    response.setHeader('content-range', `bytes ${zipPlainRange.start}-${zipPlainRange.end}/${zipInfo.plainSize}`)
  } else if (response.statusCode < 300) {
    response.statusCode = 200
    response.removeHeader('content-range')
  }
  response.setHeader('accept-ranges', 'bytes')
  response.setHeader('content-length', String(zipPlainRange.end - zipPlainRange.start + 1))
  response.setHeader('content-type', getMimeByName(request.zipVirtualName || zipInfo.origName || zipInfo.innerName || request.url))
  response.removeHeader('content-encoding')
  response.removeHeader('transfer-encoding')
}

class ZipPackageEnc {
  constructor(password, fileSize = 0, options = {}) {
    this.password = password
    this.plainSize = Number(fileSize) || 0
    this.options = options || {}
    this.zipInfo = this.options.zipInfo || null
    this.zipMode = normalizeZipMode(this.zipInfo ? this.zipInfo.zipMode : this.options.zipMode)
    this.passwdOutward = deriveOutwardPassword(password)
    this.innerName = this.options.innerName || getInnerName(this.options.originalName || this.options.origName || INNER_FILENAME)
    this.originalName = normalizeName(this.options.originalName || this.options.origName || this.innerName)
    this.salt = this.zipInfo && this.zipInfo.salt ? Buffer.from(this.zipInfo.salt) : crypto.randomBytes(SALT_SIZE)
    this.nonce = this.zipInfo && this.zipInfo.nonce ? Buffer.from(this.zipInfo.nonce) : crypto.randomBytes(NONCE_SIZE)
    this.winZipAesSalt =
      this.zipInfo && this.zipInfo.salt && this.zipInfo.zipMode === ZIP_MODE_WINZIP_AES
        ? Buffer.from(this.zipInfo.salt)
        : crypto.randomBytes(WINZIP_AES_SALT_SIZE)
    this.key = deriveKey(password, this.salt)
    this.winZipAesKeys = this.zipMode === ZIP_MODE_WINZIP_AES ? deriveWinZipAesKeys(password, this.winZipAesSalt) : null
    this.position = 0
    this.skipBytes = 0
    this.cipher = createCtrCipher(this.key, this.nonce, 0)
    this.winZipAesCipher = this.winZipAesKeys ? createWinZipAesCtr(this.winZipAesKeys.encKey, 0) : null
    this.winZipAesHmac = this.winZipAesKeys ? crypto.createHmac('sha1', this.winZipAesKeys.macKey) : null
    this.zipCrypto = null
  }

  static packageSize(plainSize, options = {}) {
    const layout = buildPackageLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || INNER_FILENAME,
      innerName: options.innerName,
      zipMode: options.zipMode,
      password: options.password || '',
    })
    return layout.packageSize
  }

  static layout(plainSize, options = {}) {
    return buildPackageLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || INNER_FILENAME,
      innerName: options.innerName,
      zipMode: options.zipMode,
      password: options.password || '',
    })
  }

  async setPositionAsync(position = 0) {
    this.position = Number(position) || 0
    if (this.zipInfo && this.zipInfo.zipMode === ZIP_MODE_COMPATIBLE) {
      const checkpoint = findCompatibleCheckpoint(this.zipInfo, this.position)
      this.skipBytes = this.position - checkpoint.offset
      this.zipCrypto = new ZipCrypto()
      this.zipCrypto.setState(checkpoint.state)
      return
    }
    this.skipBytes = 0
    if (this.zipInfo && this.zipInfo.zipMode === ZIP_MODE_WINZIP_AES) {
      this.winZipAesSalt = Buffer.from(this.zipInfo.salt)
      this.winZipAesKeys = deriveWinZipAesKeys(this.password, this.winZipAesSalt)
      this.winZipAesCipher = createWinZipAesCtr(this.winZipAesKeys.encKey, this.position)
      this.winZipAesHmac = crypto.createHmac('sha1', this.winZipAesKeys.macKey)
      return
    }
    this.cipher = createCtrCipher(this.key, this.nonce, this.position)
  }

  encryptTransform() {
    if (this.zipMode === ZIP_MODE_COMPATIBLE) return this.compatibleEncryptTransform()
    if (this.zipMode === ZIP_MODE_WINZIP_AES) return this.winZipAesEncryptTransform()
    return this.fakeEncryptTransform()
  }

  compatibleEncryptTransform() {
    const layout = buildPackageLayout({
      plainSize: this.plainSize,
      originalName: this.originalName,
      innerName: this.innerName,
      zipMode: ZIP_MODE_COMPATIBLE,
    })
    const localExtra = buildCustomExtra({ zipMode: ZIP_MODE_COMPATIBLE, checkpoints: Buffer.alloc(0) })
    const header = buildLocalHeader({
      plainSize: this.plainSize,
      compressedSize: this.plainSize + ZIPCRYPTO_HEADER_SIZE,
      innerName: layout.innerName,
      customExtra: localExtra,
    })
    const { interval } = checkpointLayout(this.plainSize)
    const zipCrypto = new ZipCrypto()
    zipCrypto.initPassword(this.password)
    const checkByte = (FIXED_DOS_TIME >> 8) & 0xff
    const encryptedHeader = zipCrypto.encrypt(Buffer.concat([crypto.randomBytes(11), Buffer.from([checkByte])]))
    const checkpoints = [{ offset: 0, state: zipCrypto.getState() }]
    let nextCheckpoint = interval
    let written = 0
    let crc = 0
    let started = false
    const self = this

    function encryptPlain(plain, stream) {
      let offset = 0
      crc = crc32(plain, crc)
      while (offset < plain.length) {
        let take = plain.length - offset
        if (checkpoints.length < CHECKPOINT_LIMIT && written < nextCheckpoint && written + take > nextCheckpoint) {
          take = nextCheckpoint - written
        }
        const piece = plain.subarray(offset, offset + take)
        stream.push(zipCrypto.encrypt(piece))
        written += piece.length
        offset += piece.length
        while (checkpoints.length < CHECKPOINT_LIMIT && written >= nextCheckpoint) {
          checkpoints.push({ offset: nextCheckpoint, state: zipCrypto.getState() })
          nextCheckpoint += interval
        }
      }
    }

    return new Transform({
      transform(chunk, encoding, next) {
        if (!started) {
          this.push(header)
          this.push(encryptedHeader)
          started = true
        }
        encryptPlain(chunk, this)
        next()
      },
      flush(next) {
        if (!started) {
          this.push(header)
          this.push(encryptedHeader)
        }
        const centralExtra = buildCustomExtra({
          zipMode: ZIP_MODE_COMPATIBLE,
          checkpoints: encodeCheckpoints(interval, checkpoints),
        })
        const tail = buildTail({
          crc,
          plainSize: written || self.plainSize,
          compressedSize: (written || self.plainSize) + ZIPCRYPTO_HEADER_SIZE,
          innerName: layout.innerName,
          customExtra: centralExtra,
          headerSize: header.length,
        })
        this.push(tail)
        next()
      },
    })
  }

  fakeEncryptTransform() {
    const customExtra = buildCustomExtra({ zipMode: ZIP_MODE_FAKE, salt: this.salt, nonce: this.nonce })
    const header = buildLocalHeader({
      plainSize: this.plainSize,
      compressedSize: this.plainSize,
      innerName: this.innerName,
      customExtra,
    })
    let started = false
    let encryptedCrc = 0
    let written = 0
    const cipher = createCtrCipher(this.key, this.nonce, 0)
    const self = this

    return new Transform({
      transform(chunk, encoding, next) {
        if (!started) {
          this.push(header)
          started = true
        }
        const encrypted = cipher.update(chunk)
        encryptedCrc = crc32(encrypted, encryptedCrc)
        written += chunk.length
        next(null, encrypted)
      },
      flush(next) {
        if (!started) {
          this.push(header)
        }
        const final = cipher.final()
        if (final.length) {
          encryptedCrc = crc32(final, encryptedCrc)
          this.push(final)
        }
        const tail = buildTail({
          crc: encryptedCrc,
          plainSize: written || self.plainSize,
          compressedSize: written || self.plainSize,
          innerName: self.innerName,
          customExtra,
          headerSize: header.length,
        })
        this.push(tail)
        next()
      },
    })
  }

  winZipAesEncryptTransform() {
    this.winZipAesSalt = crypto.randomBytes(WINZIP_AES_SALT_SIZE)
    this.winZipAesKeys = deriveWinZipAesKeys(this.password, this.winZipAesSalt)
    const aesExtra = buildWinZipAesExtra()
    const meta = buildEncryptedMeta(this.password, this.originalName, this.innerName, ZIP_MODE_WINZIP_AES)
    const customExtra = buildCustomExtra({ zipMode: ZIP_MODE_WINZIP_AES, salt: this.winZipAesSalt, meta })
    const compressedSize = this.plainSize + WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE + WINZIP_AES_AUTH_SIZE
    const header = buildLocalHeader({
      plainSize: this.plainSize,
      compressedSize,
      innerName: this.innerName,
      customExtra: Buffer.concat([customExtra, aesExtra]),
      method: WINZIP_AES_METHOD,
    })
    let started = false
    let written = 0
    const cipher = createWinZipAesCtr(this.winZipAesKeys.encKey, 0)
    const hmac = crypto.createHmac('sha1', this.winZipAesKeys.macKey)
    const self = this

    return new Transform({
      transform(chunk, encoding, next) {
        if (!started) {
          this.push(header)
          this.push(self.winZipAesSalt)
          this.push(self.winZipAesKeys.verifier)
          started = true
        }
        const encrypted = cipher.update(chunk)
        hmac.update(encrypted)
        written += chunk.length
        next(null, encrypted)
      },
      flush(next) {
        if (!started) {
          this.push(header)
          this.push(self.winZipAesSalt)
          this.push(self.winZipAesKeys.verifier)
        }
        const final = cipher.final()
        if (final.length) {
          hmac.update(final)
          this.push(final)
        }
        this.push(hmac.digest().subarray(0, WINZIP_AES_AUTH_SIZE))
        const tail = buildTail({
          crc: 0,
          plainSize: written || self.plainSize,
          compressedSize: (written || self.plainSize) + WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE + WINZIP_AES_AUTH_SIZE,
          innerName: self.innerName,
          customExtra: Buffer.concat([customExtra, aesExtra]),
          headerSize: header.length,
          method: WINZIP_AES_METHOD,
        })
        this.push(tail)
        next()
      },
    })
  }

  decryptTransform() {
    if (this.zipMode === ZIP_MODE_COMPATIBLE) return this.compatibleDecryptTransform()
    if (this.zipMode === ZIP_MODE_WINZIP_AES) return this.winZipAesDecryptTransform()
    return this.fakeDecryptTransform()
  }

  compatibleDecryptTransform() {
    const self = this
    return new Transform({
      transform(chunk, encoding, next) {
        let decrypted = self.zipCrypto.decrypt(chunk)
        if (self.skipBytes) {
          decrypted = decrypted.subarray(Math.min(self.skipBytes, decrypted.length))
          self.skipBytes = Math.max(0, self.skipBytes - chunk.length)
        }
        next(null, decrypted)
      },
    })
  }

  fakeDecryptTransform() {
    const self = this
    return new Transform({
      transform(chunk, encoding, next) {
        next(null, self.cipher.update(chunk))
      },
      flush(next) {
        const final = self.cipher.final()
        if (final.length) {
          this.push(final)
        }
        next()
      },
    })
  }

  winZipAesDecryptTransform() {
    const self = this
    return new Transform({
      transform(chunk, encoding, next) {
        next(null, self.winZipAesCipher.update(chunk))
      },
      flush(next) {
        const final = self.winZipAesCipher.final()
        if (final.length) {
          this.push(final)
        }
        next()
      },
    })
  }
}

export default ZipPackageEnc
