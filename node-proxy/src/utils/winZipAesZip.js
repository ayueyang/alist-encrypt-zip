import crypto from 'crypto'
import http from 'http'
import https from 'node:https'
import path from 'path'
import { Transform } from 'stream'
import { getMimeByName } from './mimeUtil'

export const ZIP_AES_ENC_TYPE = 'winzip-aes-ctr'
export { getMimeByName }

const ZIP64_EXTRA_ID = 0x0001
const WINZIP_AES_EXTRA_ID = 0x9901
const WINZIP_AES_METHOD = 99
const STORE_METHOD = 0
const ZIP32_MAX = 0xffffffff
const ZIP_AES_VERSION_NEEDED = 51
const ZIP_AES_FLAGS = 0x0001 | 0x0800
const WINZIP_AES_VERSION = 2
const WINZIP_AES_STRENGTH = 3
const WINZIP_AES_VENDOR = Buffer.from('AE', 'ascii')
const WINZIP_AES_SALT_SIZE = 16
const WINZIP_AES_VERIFY_SIZE = 2
const WINZIP_AES_AUTH_SIZE = 10
const WINZIP_AES_PBKDF2_ITERATIONS = 1000
const FIXED_DOS_TIME = 0x4800
const FIXED_DOS_DATE = 0x5a2a
const INNER_FILENAME = 'payload.bin'

function readUInt64LE(buffer, offset) {
  const value = buffer.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('zip file is too large for javascript number precision')
  }
  return Number(value)
}

function uint64Buffer(value) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64LE(BigInt(value), 0)
  return buffer
}

function isZip64Needed(plainSize, compressedSize = plainSize, localHeaderOffset = 0, centralOffset = 0, centralSize = 0) {
  return (
    plainSize >= ZIP32_MAX ||
    compressedSize >= ZIP32_MAX ||
    localHeaderOffset >= ZIP32_MAX ||
    centralOffset >= ZIP32_MAX ||
    centralSize >= ZIP32_MAX
  )
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value)
  } catch (e) {
    return value
  }
}

function normalizeName(name) {
  return path.basename(safeDecodeURIComponent(name || INNER_FILENAME)) || INNER_FILENAME
}

function getInnerName(name) {
  const ext = path.extname(normalizeName(name)).toLowerCase()
  return `payload${ext || '.bin'}`
}

function deriveOutwardPassword(password) {
  if (String(password || '').length === 32) {
    return password
  }
  return crypto.pbkdf2Sync(String(password || ''), 'ZIP-AES-CTR', 1000, 16, 'sha256').toString('hex')
}

function winZipAesKeySize(strength) {
  if (strength === 1) return 16
  if (strength === 2) return 24
  if (strength === 3) return 32
  throw new Error('unsupported WinZip AES strength')
}

function deriveWinZipAesKeys(password, salt, strength = WINZIP_AES_STRENGTH) {
  const keySize = winZipAesKeySize(strength)
  const material = crypto.pbkdf2Sync(
    Buffer.from(String(password || ''), 'utf8'),
    salt,
    WINZIP_AES_PBKDF2_ITERATIONS,
    keySize * 2 + WINZIP_AES_VERIFY_SIZE,
    'sha1'
  )
  return {
    encKey: material.subarray(0, keySize),
    macKey: material.subarray(keySize, keySize * 2),
    verifier: material.subarray(keySize * 2),
  }
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
  const ecb = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, null)
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

function winZipAesSaltSize(strength) {
  if (strength === 1) return 8
  if (strength === 2) return 12
  if (strength === 3) return 16
  throw new Error('unsupported WinZip AES strength')
}

function buildLocalHeader({ plainSize, compressedSize, innerName }) {
  const fileName = Buffer.from(innerName || INNER_FILENAME, 'utf8')
  const zip64 = isZip64Needed(plainSize, compressedSize)
  const extra = zip64
    ? Buffer.concat([buildZip64Extra({ uncompressedSize: plainSize, compressedSize }), buildWinZipAesExtra()])
    : buildWinZipAesExtra()
  const header = Buffer.alloc(30)
  header.writeUInt32LE(0x04034b50, 0)
  header.writeUInt16LE(ZIP_AES_VERSION_NEEDED, 4)
  header.writeUInt16LE(ZIP_AES_FLAGS, 6)
  header.writeUInt16LE(WINZIP_AES_METHOD, 8)
  header.writeUInt16LE(FIXED_DOS_TIME, 10)
  header.writeUInt16LE(FIXED_DOS_DATE, 12)
  header.writeUInt32LE(0, 14)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : compressedSize, 18)
  header.writeUInt32LE(zip64 ? ZIP32_MAX : plainSize, 22)
  header.writeUInt16LE(fileName.length, 26)
  header.writeUInt16LE(extra.length, 28)
  return Buffer.concat([header, fileName, extra])
}

function buildCentralDirectory({ plainSize, compressedSize, innerName, localHeaderOffset, centralOffset }) {
  const fileName = Buffer.from(innerName || INNER_FILENAME, 'utf8')
  const zip64 = isZip64Needed(plainSize, compressedSize, localHeaderOffset, centralOffset)
  const extra = zip64
    ? Buffer.concat([
        buildZip64Extra({
          uncompressedSize: plainSize,
          compressedSize,
          localHeaderOffset,
        }),
        buildWinZipAesExtra(),
      ])
    : buildWinZipAesExtra()
  const header = Buffer.alloc(46)
  header.writeUInt32LE(0x02014b50, 0)
  header.writeUInt16LE(ZIP_AES_VERSION_NEEDED, 4)
  header.writeUInt16LE(ZIP_AES_VERSION_NEEDED, 6)
  header.writeUInt16LE(ZIP_AES_FLAGS, 8)
  header.writeUInt16LE(WINZIP_AES_METHOD, 10)
  header.writeUInt16LE(FIXED_DOS_TIME, 12)
  header.writeUInt16LE(FIXED_DOS_DATE, 14)
  header.writeUInt32LE(0, 16)
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
    zip64Eocd.writeUInt16LE(ZIP_AES_VERSION_NEEDED, 12)
    zip64Eocd.writeUInt16LE(ZIP_AES_VERSION_NEEDED, 14)
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

function buildLayout({ plainSize, originalName, innerName }) {
  const zipInnerName = innerName || getInnerName(originalName)
  const compressedSize = Number(plainSize || 0) + WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE + WINZIP_AES_AUTH_SIZE
  const header = buildLocalHeader({ plainSize, compressedSize, innerName: zipInnerName })
  const centralOffset = header.length + compressedSize
  const central = buildCentralDirectory({
    plainSize,
    compressedSize,
    innerName: zipInnerName,
    localHeaderOffset: 0,
    centralOffset,
  })
  const zip64 = isZip64Needed(plainSize, compressedSize, 0, centralOffset, central.length)
  const endRecords = buildEndRecords({ centralOffset, centralSize: central.length, zip64 })
  return {
    header,
    central,
    endRecords,
    innerName: zipInnerName,
    headerSize: header.length,
    payloadOffset: header.length + WINZIP_AES_SALT_SIZE + WINZIP_AES_VERIFY_SIZE,
    plainSize,
    compressedSize,
    packageSize: header.length + compressedSize + central.length + endRecords.length,
  }
}

function parseRange(rangeHeader, totalSize) {
  if (totalSize <= 0) {
    return { hasRange: !!rangeHeader, start: 0, end: -1 }
  }
  if (!rangeHeader) {
    return { hasRange: false, start: 0, end: Math.max(0, totalSize - 1) }
  }
  const rangeSpec = String(rangeHeader).replace(/bytes=/i, '').trim()
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

function sanitizeForwardHeaders(headers = {}, options = {}) {
  const result = { ...headers }
  delete result.host
  delete result.Host
  delete result.range
  delete result.Range
  delete result['content-length']
  delete result['Content-Length']
  delete result['content-range']
  delete result['Content-Range']
  delete result['transfer-encoding']
  delete result['Transfer-Encoding']
  delete result['accept-encoding']
  delete result['Accept-Encoding']
  delete result['content-type']
  delete result['Content-Type']
  delete result.depth
  delete result.Depth
  if (options.stripAuth) {
    delete result.authorization
    delete result.Authorization
    delete result.referer
    delete result.Referer
  }
  return result
}

function requestBuffer(urlAddr, options, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(urlAddr)
    const httpRequest = urlObj.protocol === 'https:' ? https : http
    const { maxBytes, ...requestOptions } = options
    const headers = { ...(requestOptions.headers || {}) }
    if (urlAddr.includes('baidupcs.com')) {
      headers['User-Agent'] = 'pan.baidu.com'
    }
    const req = httpRequest.request(
      urlObj,
      {
        ...requestOptions,
        headers,
        rejectUnauthorized: false,
      },
      (resp) => {
        const location = resp.headers.location
        if (resp.statusCode >= 300 && resp.statusCode < 400 && location && redirectCount < 5) {
          resp.resume()
          const nextUrl = new URL(location, urlObj).toString()
          const nextUrlObj = new URL(nextUrl)
          const nextOptions = { ...options, headers: { ...(options.headers || {}) } }
          delete nextOptions.headers.host
          delete nextOptions.headers.Host
          if (urlObj.host !== nextUrlObj.host) {
            delete nextOptions.headers.authorization
            delete nextOptions.headers.Authorization
            delete nextOptions.headers.referer
            delete nextOptions.headers.Referer
          }
          if (nextUrl.includes('baidupcs.com')) {
            nextOptions.headers['User-Agent'] = 'pan.baidu.com'
          }
          requestBuffer(nextUrl, nextOptions, redirectCount + 1).then(resolve).catch(reject)
          return
        }
        const chunks = []
        let total = 0
        resp.on('data', (chunk) => {
          total += chunk.length
          if (maxBytes && total > maxBytes) {
            req.destroy(new Error('remote response exceeded expected range size'))
            return
          }
          chunks.push(chunk)
        })
        resp.on('end', () => resolve({ statusCode: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks), url: urlAddr }))
      }
    )
    req.on('error', reject)
    req.end()
  })
}

async function getRemoteSize(urlAddr, headers, candidateSize = 0, options = {}) {
  if (candidateSize > 0) return candidateSize
  const cleanHeaders = sanitizeForwardHeaders(headers, options)
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
  throw new Error('unable to detect remote WinZip-AES-CTR ZIP size')
}

async function readRemoteRange(urlAddr, headers, start, length, options = {}) {
  const end = start + length - 1
  const cleanHeaders = sanitizeForwardHeaders(headers, options)
  const resp = await requestBuffer(urlAddr, {
    method: 'GET',
    headers: { ...cleanHeaders, Range: `bytes=${start}-${end}` },
    maxBytes: length,
  })
  if (resp.statusCode === 206) {
    return resp.body
  }
  throw new Error(`remote range request failed: ${resp.statusCode}`)
}

async function parseEocd(tail, tailStart, readRange) {
  const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06])
  let pos = -1
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.subarray(i, i + 4).equals(eocdSig)) {
      const commentLen = tail.readUInt16LE(i + 20)
      if (i + 22 + commentLen === tail.length) {
        pos = i
        break
      }
    }
  }
  if (pos < 0 || pos + 22 > tail.length) {
    throw new Error('ZIP EOCD not found')
  }
  const eocd = tail.subarray(pos, pos + 22)
  let entryCount = eocd.readUInt16LE(10)
  let centralSize = eocd.readUInt32LE(12)
  let centralOffset = eocd.readUInt32LE(16)
  const needsZip64 = centralSize === ZIP32_MAX || centralOffset === ZIP32_MAX || eocd.readUInt16LE(8) === 0xffff

  if (!needsZip64) {
    return { centralOffset, centralSize, entryCount }
  }

  const locatorSig = Buffer.from([0x50, 0x4b, 0x06, 0x07])
  const locatorPos = tail.lastIndexOf(locatorSig, pos)
  if (locatorPos < 0 || locatorPos + 20 > tail.length) {
    throw new Error('ZIP64 locator not found')
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
    throw new Error('ZIP64 EOCD is invalid')
  }
  entryCount = readUInt64LE(zip64Eocd, 32)
  centralSize = readUInt64LE(zip64Eocd, 40)
  centralOffset = readUInt64LE(zip64Eocd, 48)
  return { centralOffset, centralSize, entryCount }
}

function parseLocalHeaderBytes(fixed, rest, localHeaderOffset) {
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
    method: fixed.readUInt16LE(8),
    flags: fixed.readUInt16LE(6),
    compressedSize: zip64.compressedSize ?? compressedSize32,
    uncompressedSize: zip64.uncompressedSize ?? uncompressedSize32,
    localHeaderOffset,
    name,
    extra,
    headerSize: 30 + nameLen + extraLen,
  }
}

async function parseLocalHeader(readRange, localHeaderOffset) {
  const fixed = await readRange(localHeaderOffset, 30)
  if (fixed.length < 30 || fixed.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('ZIP local header is invalid')
  }
  const nameLen = fixed.readUInt16LE(26)
  const extraLen = fixed.readUInt16LE(28)
  const rest = await readRange(localHeaderOffset + 30, nameLen + extraLen)
  return parseLocalHeaderBytes(fixed, rest, localHeaderOffset)
}

async function parseCentralDirectory(readRange, centralOffset) {
  const fixed = await readRange(centralOffset, 46)
  if (fixed.length < 46 || fixed.readUInt32LE(0) !== 0x02014b50) {
    throw new Error('ZIP central directory header is invalid')
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
    method: fixed.readUInt16LE(10),
    flags: fixed.readUInt16LE(8),
    compressedSize: zip64.compressedSize ?? compressedSize32,
    uncompressedSize: zip64.uncompressedSize ?? uncompressedSize32,
    localHeaderOffset: zip64.localHeaderOffset ?? localHeaderOffset32,
    name,
    extra,
  }
}

export async function parseWinZipAesZipInfoFromReader(readRange, totalSize) {
  const tailSize = Math.min(65536 + 128, totalSize)
  const tailStart = Math.max(0, totalSize - tailSize)
  const tail = await readRange(tailStart, totalSize - tailStart)
  const { centralOffset, entryCount } = await parseEocd(tail, tailStart, readRange)
  if (entryCount !== 1) {
    throw new Error('WinZip AES playback supports single-file ZIP only')
  }
  const central = await parseCentralDirectory(readRange, centralOffset)
  const local = await parseLocalHeader(readRange, central.localHeaderOffset)
  const winZipAes = parseWinZipAesExtra(central.extra) || parseWinZipAesExtra(local.extra)
  if (!winZipAes) {
    throw new Error('WinZip AES extra field not found')
  }
  if (winZipAes.vendor !== WINZIP_AES_VENDOR.toString('ascii')) {
    throw new Error('WinZip AES vendor is invalid')
  }
  if ((central.flags & 1) === 0 || (local.flags & 1) === 0) {
    throw new Error('ZIP entry is not encrypted')
  }
  if (central.method !== WINZIP_AES_METHOD || local.method !== WINZIP_AES_METHOD) {
    throw new Error('ZIP entry is not WinZip AES')
  }
  if (winZipAes.actualMethod !== STORE_METHOD) {
    throw new Error('WinZip AES playback requires store method')
  }
  const saltLen = winZipAesSaltSize(winZipAes.strength)
  const dataHeaderSize = saltLen + WINZIP_AES_VERIFY_SIZE
  const authSize = WINZIP_AES_AUTH_SIZE
  const plainSize = central.uncompressedSize
  const compressedSize = central.compressedSize
  if (compressedSize - dataHeaderSize - authSize !== plainSize) {
    throw new Error('WinZip-AES-CTR ZIP is not store-compatible')
  }
  const saltOffset = local.localHeaderOffset + local.headerSize
  const salt = await readRange(saltOffset, saltLen)
  return {
    encType: ZIP_AES_ENC_TYPE,
    innerName: central.name || local.name || INNER_FILENAME,
    salt,
    winZipAes,
    headerSize: local.headerSize,
    localHeaderOffset: local.localHeaderOffset,
    payloadOffset: saltOffset + dataHeaderSize,
    payloadSize: plainSize,
    authTagOffset: saltOffset + compressedSize - authSize,
    authSize,
    plainSize,
    compressedSize,
    totalSize,
  }
}

export async function parseManagedWinZipAesZipInfoFromReader(readRange, totalSize) {
  const firstSize = Math.min(4096, totalSize)
  let first = await readRange(0, firstSize)
  const ensureFirstBytes = async (length) => {
    if (first.length >= length) return first.subarray(0, length)
    const next = await readRange(first.length, length - first.length)
    first = Buffer.concat([first, next])
    return first.subarray(0, length)
  }

  const fixed = await ensureFirstBytes(30)
  if (fixed.length < 30 || fixed.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('ZIP local header is invalid')
  }
  const nameLen = fixed.readUInt16LE(26)
  const extraLen = fixed.readUInt16LE(28)
  const headerSize = 30 + nameLen + extraLen
  const header = await ensureFirstBytes(headerSize)
  const local = parseLocalHeaderBytes(fixed, header.subarray(30, headerSize), 0)
  const winZipAes = parseWinZipAesExtra(local.extra)
  if (!winZipAes) {
    throw new Error('WinZip AES extra field not found')
  }
  if (winZipAes.vendor !== WINZIP_AES_VENDOR.toString('ascii')) {
    throw new Error('WinZip AES vendor is invalid')
  }
  if ((local.flags & 1) === 0) {
    throw new Error('ZIP entry is not encrypted')
  }
  if (local.method !== WINZIP_AES_METHOD) {
    throw new Error('ZIP entry is not WinZip AES')
  }
  if (winZipAes.actualMethod !== STORE_METHOD) {
    throw new Error('WinZip AES playback requires store method')
  }

  const saltLen = winZipAesSaltSize(winZipAes.strength)
  const dataHeaderSize = saltLen + WINZIP_AES_VERIFY_SIZE
  const authSize = WINZIP_AES_AUTH_SIZE
  const plainSize = local.uncompressedSize
  const compressedSize = local.compressedSize
  if (compressedSize - dataHeaderSize - authSize !== plainSize) {
    throw new Error('WinZip-AES-CTR ZIP is not store-compatible')
  }
  const saltOffset = local.headerSize
  const saltBytes = await ensureFirstBytes(saltOffset + saltLen)
  return {
    encType: ZIP_AES_ENC_TYPE,
    innerName: local.name || INNER_FILENAME,
    salt: saltBytes.subarray(saltOffset, saltOffset + saltLen),
    winZipAes,
    headerSize: local.headerSize,
    localHeaderOffset: 0,
    payloadOffset: saltOffset + dataHeaderSize,
    payloadSize: plainSize,
    authTagOffset: saltOffset + compressedSize - authSize,
    authSize,
    plainSize,
    compressedSize,
    totalSize,
  }
}

export async function parseWinZipAesZipInfoFromFile(filePath) {
  const fs = await import('fs')
  const stat = await fs.promises.stat(filePath)
  const handle = await fs.promises.open(filePath, 'r')
  try {
    const readRange = async (start, length) => {
      const buffer = Buffer.alloc(length)
      const result = await handle.read(buffer, 0, length, start)
      return buffer.subarray(0, result.bytesRead)
    }
    return await parseWinZipAesZipInfoFromReader(readRange, stat.size)
  } finally {
    await handle.close()
  }
}

export async function parseManagedWinZipAesZipInfoFromFile(filePath) {
  const fs = await import('fs')
  const stat = await fs.promises.stat(filePath)
  const handle = await fs.promises.open(filePath, 'r')
  try {
    const readRange = async (start, length) => {
      const buffer = Buffer.alloc(length)
      const result = await handle.read(buffer, 0, length, start)
      return buffer.subarray(0, result.bytesRead)
    }
    return await parseManagedWinZipAesZipInfoFromReader(readRange, stat.size)
  } finally {
    await handle.close()
  }
}

export async function parseWinZipAesZipInfoFromRemote(urlAddr, headers = {}, candidateSize = 0, options = {}) {
  const totalSize = await getRemoteSize(urlAddr, headers, Number(candidateSize) || 0, options)
  const readRange = (start, length) => readRemoteRange(urlAddr, headers, start, length, options)
  return await parseWinZipAesZipInfoFromReader(readRange, totalSize)
}

export async function parseManagedWinZipAesZipInfoFromRemote(urlAddr, headers = {}, candidateSize = 0, options = {}) {
  const totalSize = await getRemoteSize(urlAddr, headers, Number(candidateSize) || 0, options)
  const readRange = (start, length) => readRemoteRange(urlAddr, headers, start, length, options)
  return await parseManagedWinZipAesZipInfoFromReader(readRange, totalSize)
}

export function isWinZipAesEncType(encType) {
  return encType === ZIP_AES_ENC_TYPE
}

export function serializeWinZipAesZipInfo(zipInfo) {
  if (!zipInfo) return null
  return {
    ...zipInfo,
    salt: zipInfo.salt ? Buffer.from(zipInfo.salt).toString('hex') : undefined,
  }
}

export function deserializeWinZipAesZipInfo(zipInfo) {
  if (!zipInfo || !isWinZipAesEncType(zipInfo.encType)) return null
  return {
    ...zipInfo,
    salt: zipInfo.salt ? Buffer.from(zipInfo.salt, 'hex') : undefined,
  }
}

export function prepareWinZipAesDownloadRequest(request, zipInfo, clientRangeHeader) {
  const plainRange = parseRange(clientRangeHeader, zipInfo.plainSize)
  request.zipInfo = zipInfo
  request.zipPlainRange = plainRange
  request.zipCipherStart = plainRange.start
  delete request.headers['accept-encoding']

  if (request.method.toLocaleUpperCase() !== 'HEAD') {
    const start = zipInfo.payloadOffset + plainRange.start
    const end = zipInfo.payloadOffset + plainRange.end
    request.zipPackageRange = { start, end }
    request.headers.range = `bytes=${start}-${end}`
  }
  return plainRange
}

export function applyWinZipAesResponseHeaders(response, request) {
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
  response.setHeader('content-length', String(Math.max(0, zipPlainRange.end - zipPlainRange.start + 1)))
  response.setHeader('content-type', getMimeByName(request.zipVirtualName || zipInfo.innerName || request.url))
  response.removeHeader('content-encoding')
  response.removeHeader('transfer-encoding')
}

class WinZipAesZip {
  constructor(password, fileSize = 0, options = {}) {
    this.password = password
    this.plainSize = Number(fileSize) || 0
    this.options = options || {}
    this.zipInfo = this.options.zipInfo || null
    this.passwdOutward = deriveOutwardPassword(password)
    this.innerName = this.options.innerName || getInnerName(this.options.originalName || this.options.origName || INNER_FILENAME)
    this.originalName = normalizeName(this.options.originalName || this.options.origName || this.innerName)
    this.salt = this.zipInfo && this.zipInfo.salt ? Buffer.from(this.zipInfo.salt) : crypto.randomBytes(WINZIP_AES_SALT_SIZE)
    this.strength = (this.zipInfo && this.zipInfo.winZipAes && this.zipInfo.winZipAes.strength) || WINZIP_AES_STRENGTH
    this.keys = deriveWinZipAesKeys(password, this.salt, this.strength)
    this.cipher = createWinZipAesCtr(this.keys.encKey, 0)
    this.position = 0
  }

  static packageSize(plainSize, options = {}) {
    return buildLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || INNER_FILENAME,
      innerName: options.innerName,
    }).packageSize
  }

  static layout(plainSize, options = {}) {
    return buildLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || INNER_FILENAME,
      innerName: options.innerName,
    })
  }

  async setPositionAsync(position = 0) {
    this.position = Number(position) || 0
    if (this.zipInfo && this.zipInfo.salt) {
      this.salt = Buffer.from(this.zipInfo.salt)
      this.strength = (this.zipInfo.winZipAes && this.zipInfo.winZipAes.strength) || WINZIP_AES_STRENGTH
      this.keys = deriveWinZipAesKeys(this.password, this.salt, this.strength)
    }
    this.cipher = createWinZipAesCtr(this.keys.encKey, this.position)
  }

  encryptTransform() {
    const layout = buildLayout({
      plainSize: this.plainSize,
      originalName: this.originalName,
      innerName: this.innerName,
    })
    let started = false
    let written = 0
    const cipher = createWinZipAesCtr(this.keys.encKey, 0)
    const hmac = crypto.createHmac('sha1', this.keys.macKey)
    const self = this

    return new Transform({
      transform(chunk, encoding, next) {
        if (!started) {
          this.push(layout.header)
          this.push(self.salt)
          this.push(self.keys.verifier)
          started = true
        }
        const encrypted = cipher.update(chunk)
        hmac.update(encrypted)
        written += chunk.length
        next(null, encrypted)
      },
      flush(next) {
        if (!started) {
          this.push(layout.header)
          this.push(self.salt)
          this.push(self.keys.verifier)
        }
        const final = cipher.final()
        if (final.length) {
          hmac.update(final)
          this.push(final)
        }
        if (written !== self.plainSize) {
          this.destroy(new Error('WinZip-AES-CTR ZIP upload size changed while streaming'))
          return
        }
        this.push(hmac.digest().subarray(0, WINZIP_AES_AUTH_SIZE))
        this.push(layout.central)
        this.push(layout.endRecords)
        next()
      },
    })
  }

  decryptTransform() {
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
}

export default WinZipAesZip
