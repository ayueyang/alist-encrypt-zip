'use strict'

import crypto from 'crypto'
import http from 'http'
import https from 'node:https'
import path from 'path'
import { Transform } from 'stream'
import { getMimeByName } from './mimeUtil'

export const SEVEN_ZIP_AES_CBC_ENC_TYPE = '7z-aes-cbc'
export const SEVEN_ZIP_AES_CBC_DISPLAY_NAME = '7z AES-CBC'

const SIGNATURE = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
const SIGNATURE_HEADER_SIZE = 32
const AES_BLOCK_SIZE = 16
const SEVEN_ZIP_START_POSITION_AFTER_HEADER = 32
const MAX_DERIVED_KEY_CACHE_SIZE = 64
const SEVEN_ZIP_AES_CBC_CYCLES = 19
const SEVEN_ZIP_FILE_ATTRIBUTE_ARCHIVE = 0x20
const SEVEN_ZIP_FIXED_FILE_TIME = new Date('2026-06-10T00:00:00Z').getTime()
const derivedKeyCache = new Map()
const crc32Table = new Uint32Array(256)

for (let i = 0; i < crc32Table.length; i++) {
  let value = i
  for (let j = 0; j < 8; j++) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  }
  crc32Table[i] = value >>> 0
}

const NID = {
  END: 0x00,
  HEADER: 0x01,
  ARCHIVE_PROPERTIES: 0x02,
  ADDITIONAL_STREAMS_INFO: 0x03,
  MAIN_STREAMS_INFO: 0x04,
  FILES_INFO: 0x05,
  PACK_INFO: 0x06,
  UNPACK_INFO: 0x07,
  SUB_STREAMS_INFO: 0x08,
  SIZE: 0x09,
  CRC: 0x0a,
  FOLDER: 0x0b,
  CODERS_UNPACK_SIZE: 0x0c,
  NUM_UNPACK_STREAM: 0x0d,
  EMPTY_STREAM: 0x0e,
  EMPTY_FILE: 0x0f,
  ANTI: 0x10,
  NAME: 0x11,
  ATTRIBUTES: 0x15,
  ENCODED_HEADER: 0x17,
  DUMMY: 0x19,
}

const METHOD_COPY = '00'
const METHOD_7Z_AES = '06f10701'

function readUInt64LE(buffer, offset) {
  const value = buffer.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('7z file is too large for javascript number precision')
  }
  return Number(value)
}

function normalizeSize(size) {
  return Number(size) || 0
}

function normalizeName(name) {
  return path.basename(String(name || 'payload.bin')) || 'payload.bin'
}

function getInnerName(name) {
  return normalizeName(name)
}

function encodeSevenZipNum(value) {
  const bigValue = BigInt(Number(value) || 0)
  if (bigValue < 0x80n) return Buffer.from([Number(bigValue)])
  for (let i = 1; i < 8; i++) {
    const maxValue = 1n << BigInt(7 * (i + 1))
    if (bigValue < maxValue) {
      const result = Buffer.alloc(i + 1)
      const prefix = (0xff << (8 - i)) & 0xff
      const high = Number(bigValue >> BigInt(8 * i))
      result[0] = (prefix | high) & 0xff
      for (let j = 0; j < i; j++) {
        result[j + 1] = Number((bigValue >> BigInt(8 * j)) & 0xffn)
      }
      return result
    }
  }
  const result = Buffer.alloc(9)
  result[0] = 0xff
  result.writeBigUInt64LE(bigValue, 1)
  return result
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc = crc32Table[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function uint64Buffer(value) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64LE(BigInt(Number(value) || 0), 0)
  return buffer
}

function getSevenZipFileTimeBuffer(time = SEVEN_ZIP_FIXED_FILE_TIME) {
  const buffer = Buffer.alloc(8)
  const fileTime = BigInt(Number(time) || 0) * 10000n + 116444736000000000n
  buffer.writeBigUInt64LE(fileTime, 0)
  return buffer
}

function getAesCbcProperties(iv, cycles = SEVEN_ZIP_AES_CBC_CYCLES) {
  return Buffer.concat([Buffer.from([0x40 | cycles, 0x0f]), Buffer.from(iv)])
}

function padSize(size) {
  return Math.ceil(normalizeSize(size) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
}

function buildSevenZipAesCbcFolder(iv) {
  const aesProperties = getAesCbcProperties(iv)
  return Buffer.concat([
    encodeSevenZipNum(1),
    Buffer.from([0]),
    encodeSevenZipNum(2),
    Buffer.from([0x24, 0x06, 0xf1, 0x07, 0x01]),
    encodeSevenZipNum(aesProperties.length),
    aesProperties,
    Buffer.from([0x01, 0x00]),
    encodeSevenZipNum(1),
    encodeSevenZipNum(0),
  ])
}

function buildSevenZipAesCbcStreamsInfo({ packPos, packedSize, plainSize, iv }) {
  const packInfo = Buffer.concat([
    encodeSevenZipNum(NID.PACK_INFO),
    encodeSevenZipNum(packPos),
    encodeSevenZipNum(1),
    encodeSevenZipNum(NID.SIZE),
    encodeSevenZipNum(packedSize),
    encodeSevenZipNum(NID.END),
  ])
  const unpackInfo = Buffer.concat([
    encodeSevenZipNum(NID.UNPACK_INFO),
    encodeSevenZipNum(NID.FOLDER),
    buildSevenZipAesCbcFolder(iv),
    encodeSevenZipNum(NID.CODERS_UNPACK_SIZE),
    encodeSevenZipNum(plainSize),
    encodeSevenZipNum(plainSize),
    encodeSevenZipNum(NID.END),
  ])
  return Buffer.concat([packInfo, unpackInfo, encodeSevenZipNum(NID.END)])
}

function buildSevenZipAesCbcHeader({ plainSize, packedSize, innerName, iv }) {
  const nameBytes = Buffer.concat([Buffer.from(innerName, 'utf16le'), Buffer.from([0, 0])])
  const nameBody = Buffer.concat([Buffer.from([0]), nameBytes])
  const modifiedTimeBody = Buffer.concat([Buffer.from([1, 0]), getSevenZipFileTimeBuffer()])
  const attributesBody = Buffer.alloc(6)
  attributesBody[0] = 1
  attributesBody[1] = 0
  attributesBody.writeUInt32LE(SEVEN_ZIP_FILE_ATTRIBUTE_ARCHIVE, 2)

  const filesInfo = Buffer.concat([
    encodeSevenZipNum(NID.FILES_INFO),
    encodeSevenZipNum(1),
    encodeSevenZipNum(NID.DUMMY),
    encodeSevenZipNum(0),
    encodeSevenZipNum(NID.NAME),
    encodeSevenZipNum(nameBody.length),
    nameBody,
    encodeSevenZipNum(0x14),
    encodeSevenZipNum(modifiedTimeBody.length),
    modifiedTimeBody,
    encodeSevenZipNum(NID.ATTRIBUTES),
    encodeSevenZipNum(attributesBody.length),
    attributesBody,
    encodeSevenZipNum(NID.END),
  ])

  return Buffer.concat([
    encodeSevenZipNum(NID.HEADER),
    encodeSevenZipNum(NID.MAIN_STREAMS_INFO),
    buildSevenZipAesCbcStreamsInfo({ packPos: 0, packedSize, plainSize, iv }),
    filesInfo,
    encodeSevenZipNum(NID.END),
  ])
}

function buildSevenZipEncodedHeader({ packPos, packedSize, plainSize, iv }) {
  return Buffer.concat([
    encodeSevenZipNum(NID.ENCODED_HEADER),
    buildSevenZipAesCbcStreamsInfo({ packPos, packedSize, plainSize, iv }),
  ])
}

function buildSignatureHeader(nextHeaderOffset, nextHeader) {
  const signatureHeader = Buffer.alloc(SIGNATURE_HEADER_SIZE)
  SIGNATURE.copy(signatureHeader, 0)
  signatureHeader[6] = 0
  signatureHeader[7] = 4
  uint64Buffer(nextHeaderOffset).copy(signatureHeader, 12)
  uint64Buffer(nextHeader.length).copy(signatureHeader, 20)
  signatureHeader.writeUInt32LE(crc32(nextHeader), 28)
  signatureHeader.writeUInt32LE(crc32(signatureHeader.subarray(12, 32)), 8)
  return signatureHeader
}

function buildSevenZipAesCbcLayout({ plainSize, originalName, innerName, iv, headerIv }) {
  const normalizedPlainSize = normalizeSize(plainSize)
  const archiveInnerName = getInnerName(innerName || originalName)
  const payloadPackedSize = padSize(normalizedPlainSize)
  const header = buildSevenZipAesCbcHeader({
    plainSize: normalizedPlainSize,
    packedSize: payloadPackedSize,
    innerName: archiveInnerName,
    iv,
  })
  const encodedHeaderIv = headerIv ? Buffer.from(headerIv) : Buffer.alloc(AES_BLOCK_SIZE)
  const encodedHeaderPackedSize = padSize(header.length)
  const encodedHeader = buildSevenZipEncodedHeader({
    packPos: payloadPackedSize,
    packedSize: encodedHeaderPackedSize,
    plainSize: header.length,
    iv: encodedHeaderIv,
  })
  const signatureHeader = buildSignatureHeader(payloadPackedSize + encodedHeaderPackedSize, encodedHeader)
  return {
    signatureHeader,
    header: encodedHeader,
    innerHeader: header,
    encodedHeaderPackedSize,
    encodedHeaderIv,
    innerName: archiveInnerName,
    packageSize: signatureHeader.length + payloadPackedSize + encodedHeaderPackedSize + encodedHeader.length,
    plainSize: normalizedPlainSize,
    packedSize: payloadPackedSize,
    payloadOffset: SIGNATURE_HEADER_SIZE,
    payloadSize: normalizedPlainSize,
    cycles: SEVEN_ZIP_AES_CBC_CYCLES,
    iv,
  }
}

function deriveOutwardPassword(password) {
  if (String(password || '').length === 32) {
    return password
  }
  return crypto.pbkdf2Sync(String(password || ''), '7Z-AES-CBC', 1000, 16, 'sha256').toString('hex')
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
    const { maxBytes, sliceStart, ...requestOptions } = options
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
        let skipped = 0
        let collected = 0
        let finished = false
        const done = (value) => {
          if (finished) return
          finished = true
          resolve(value)
          req.destroy()
        }
        resp.on('data', (chunk) => {
          total += chunk.length
          if (maxBytes && resp.statusCode !== 200 && total > maxBytes) {
            req.destroy(new Error('remote response exceeded expected range size'))
            return
          }
          if (resp.statusCode === 200 && maxBytes) {
            const start = Number(sliceStart) || 0
            if (skipped + chunk.length <= start) {
              skipped += chunk.length
              return
            }
            const chunkStart = Math.max(0, start - skipped)
            const remain = maxBytes - collected
            const chunkPart = chunk.subarray(chunkStart, chunkStart + remain)
            chunks.push(chunkPart)
            skipped += chunk.length
            collected += chunkPart.length
            if (collected >= maxBytes) {
              done({ statusCode: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks), url: urlAddr })
            }
            return
          }
          chunks.push(chunk)
        })
        resp.on('end', () => {
          if (!finished) resolve({ statusCode: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks), url: urlAddr })
        })
      }
    )
    req.on('error', (err) => {
      if (!String(err && err.code).includes('ECONNRESET')) reject(err)
    })
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
  throw new Error('unable to detect remote 7z AES-CBC size')
}

async function readRemoteRange(urlAddr, headers, start, length, options = {}) {
  const end = start + length - 1
  const cleanHeaders = sanitizeForwardHeaders(headers, options)
  const resp = await requestBuffer(urlAddr, {
    method: 'GET',
    headers: { ...cleanHeaders, Range: `bytes=${start}-${end}` },
    maxBytes: length,
    sliceStart: start,
  })
  if (resp.statusCode === 206) {
    return resp.body
  }
  if (resp.statusCode === 200) {
    return resp.body
  }
  throw new Error(`remote range request failed: ${resp.statusCode}`)
}

class ByteReader {
  constructor(buffer) {
    this.buffer = buffer
    this.pos = 0
  }

  rem() {
    return this.buffer.length - this.pos
  }

  readByte() {
    if (this.pos >= this.buffer.length) throw new Error('unexpected end of 7z header')
    return this.buffer[this.pos++]
  }

  readBytes(length) {
    if (length > this.rem()) throw new Error('unexpected end of 7z header')
    const value = this.buffer.subarray(this.pos, this.pos + length)
    this.pos += length
    return value
  }

  skip(length) {
    this.readBytes(length)
  }

  readUInt32() {
    const value = this.readBytes(4).readUInt32LE(0)
    return value
  }

  readUInt64() {
    return readUInt64LE(this.readBytes(8), 0)
  }

  readNum() {
    const first = this.readByte()
    if ((first & 0x80) === 0) return first
    let value = 0
    for (let i = 1; i < 8; i++) {
      const b = this.readByte()
      value |= b * Math.pow(2, 8 * (i - 1))
      const mask = 0x80 >> i
      if ((first & mask) === 0) {
        value += (first & (mask - 1)) * Math.pow(2, 8 * i)
        if (value > Number.MAX_SAFE_INTEGER) throw new Error('7z number is too large')
        return value
      }
    }
    const b = this.readByte()
    value += b * Math.pow(2, 56)
    if (value > Number.MAX_SAFE_INTEGER) throw new Error('7z number is too large')
    return value
  }

  readId() {
    return this.readNum()
  }

  readBoolVector(numItems) {
    const result = []
    let mask = 0
    let value = 0
    for (let i = 0; i < numItems; i++) {
      if (mask === 0) {
        value = this.readByte()
        mask = 0x80
      }
      result.push((value & mask) !== 0)
      mask >>= 1
    }
    return result
  }

  readBoolVector2(numItems) {
    const allAreDefined = this.readByte()
    if (allAreDefined !== 0) {
      return Array(numItems).fill(true)
    }
    return this.readBoolVector(numItems)
  }
}

function methodIdToHex(id) {
  return Buffer.from(id).toString('hex')
}

function skipHashDigests(reader, numItems) {
  const defined = reader.readBoolVector2(numItems)
  for (const itemDefined of defined) {
    if (itemDefined) reader.skip(4)
  }
}

function readPackInfo(reader) {
  const packPos = reader.readNum()
  const numPackStreams = reader.readNum()
  const packSizes = []
  let type = reader.readId()
  if (type !== NID.SIZE) throw new Error('7z PackInfo sizes not found')
  for (let i = 0; i < numPackStreams; i++) {
    packSizes.push(reader.readNum())
  }
  for (;;) {
    type = reader.readId()
    if (type === NID.END) break
    if (type === NID.CRC) {
      skipHashDigests(reader, numPackStreams)
    } else {
      reader.skip(reader.readNum())
    }
  }
  return { packPos, numPackStreams, packSizes }
}

function readCoder(reader) {
  const mainByte = reader.readByte()
  if ((mainByte & 0xc0) !== 0) throw new Error('unsupported 7z coder flags')
  const idSize = mainByte & 0x0f
  const id = reader.readBytes(idSize)
  let numInStreams = 1
  let numOutStreams = 1
  if ((mainByte & 0x10) !== 0) {
    numInStreams = reader.readNum()
    numOutStreams = reader.readNum()
  }
  let properties = Buffer.alloc(0)
  if ((mainByte & 0x20) !== 0) {
    properties = reader.readBytes(reader.readNum())
  }
  return {
    method: methodIdToHex(id),
    id,
    numInStreams,
    numOutStreams,
    properties,
  }
}

function readFolder(reader) {
  const numCoders = reader.readNum()
  if (numCoders <= 0) throw new Error('7z folder has no coder')
  const coders = []
  let numInStreamsTotal = 0
  let numOutStreamsTotal = 0
  for (let i = 0; i < numCoders; i++) {
    const coder = readCoder(reader)
    coders.push(coder)
    numInStreamsTotal += coder.numInStreams
    numOutStreamsTotal += coder.numOutStreams
  }
  const numBindPairs = numOutStreamsTotal - 1
  const bindPairs = []
  const boundInStreams = new Set()
  for (let i = 0; i < numBindPairs; i++) {
    const inIndex = reader.readNum()
    const outIndex = reader.readNum()
    bindPairs.push({ inIndex, outIndex })
    boundInStreams.add(inIndex)
  }
  const numPackedStreams = numInStreamsTotal - numBindPairs
  const packedStreams = []
  if (numPackedStreams === 1) {
    for (let i = 0; i < numInStreamsTotal; i++) {
      if (!boundInStreams.has(i)) {
        packedStreams.push(i)
        break
      }
    }
  } else {
    for (let i = 0; i < numPackedStreams; i++) {
      packedStreams.push(reader.readNum())
    }
  }
  return {
    coders,
    bindPairs,
    packedStreams,
    numInStreamsTotal,
    numOutStreamsTotal,
  }
}

function readUnpackInfo(reader) {
  let type = reader.readId()
  if (type !== NID.FOLDER) throw new Error('7z Folder info not found')
  const numFolders = reader.readNum()
  const external = reader.readByte()
  if (external !== 0) throw new Error('external 7z folder info is not supported')
  const folders = []
  for (let i = 0; i < numFolders; i++) {
    folders.push(readFolder(reader))
  }

  type = reader.readId()
  if (type !== NID.CODERS_UNPACK_SIZE) throw new Error('7z coder unpack sizes not found')
  for (const folder of folders) {
    folder.unpackSizes = []
    for (let i = 0; i < folder.numOutStreamsTotal; i++) {
      folder.unpackSizes.push(reader.readNum())
    }
  }

  for (;;) {
    type = reader.readId()
    if (type === NID.END) break
    if (type === NID.CRC) {
      skipHashDigests(reader, numFolders)
    } else {
      reader.skip(reader.readNum())
    }
  }
  return { folders }
}

function getFolderUnpackSize(folder) {
  const boundOutStreams = new Set(folder.bindPairs.map((item) => item.outIndex))
  for (let i = folder.numOutStreamsTotal - 1; i >= 0; i--) {
    if (!boundOutStreams.has(i)) {
      return folder.unpackSizes[i]
    }
  }
  return folder.unpackSizes[folder.unpackSizes.length - 1] || 0
}

function readSubStreamsInfo(reader, folders) {
  const numUnpackStreamsInFolders = folders.map(() => 1)
  const unpackSizes = []
  const digestsDefined = []
  let type = reader.readId()
  if (type === NID.NUM_UNPACK_STREAM) {
    for (let i = 0; i < folders.length; i++) {
      numUnpackStreamsInFolders[i] = reader.readNum()
    }
    type = reader.readId()
  }
  let totalUnpackStreams = 0
  for (const count of numUnpackStreamsInFolders) totalUnpackStreams += count

  if (type === NID.SIZE) {
    for (let i = 0; i < folders.length; i++) {
      let sum = 0
      for (let j = 1; j < numUnpackStreamsInFolders[i]; j++) {
        const size = reader.readNum()
        unpackSizes.push(size)
        sum += size
      }
      unpackSizes.push(getFolderUnpackSize(folders[i]) - sum)
    }
    type = reader.readId()
  } else {
    for (let i = 0; i < folders.length; i++) {
      unpackSizes.push(getFolderUnpackSize(folders[i]))
    }
  }

  if (type === NID.CRC) {
    const defined = reader.readBoolVector2(totalUnpackStreams)
    for (const itemDefined of defined) {
      digestsDefined.push(itemDefined)
      if (itemDefined) reader.skip(4)
    }
    type = reader.readId()
  }
  while (type !== NID.END) {
    reader.skip(reader.readNum())
    type = reader.readId()
  }
  return { numUnpackStreamsInFolders, unpackSizes, digestsDefined }
}

function readStreamsInfo(reader) {
  let type = reader.readId()
  let packInfo = null
  let unpackInfo = { folders: [] }
  let subStreamsInfo = null
  if (type === NID.PACK_INFO) {
    packInfo = readPackInfo(reader)
    type = reader.readId()
  }
  if (type === NID.UNPACK_INFO) {
    unpackInfo = readUnpackInfo(reader)
    type = reader.readId()
  }
  if (type === NID.SUB_STREAMS_INFO) {
    subStreamsInfo = readSubStreamsInfo(reader, unpackInfo.folders)
    type = reader.readId()
  } else if (unpackInfo.folders.length) {
    subStreamsInfo = {
      numUnpackStreamsInFolders: unpackInfo.folders.map(() => 1),
      unpackSizes: unpackInfo.folders.map(getFolderUnpackSize),
      digestsDefined: [],
    }
  }
  if (type !== NID.END) throw new Error('7z StreamsInfo is invalid')
  return { packInfo, folders: unpackInfo.folders, subStreamsInfo }
}

function readExternalDataProperty(reader, dataVector) {
  const external = reader.readByte()
  if (external === 0) {
    return reader.readBytes(reader.rem())
  }
  const dataIndex = reader.readNum()
  if (!dataVector || !dataVector[dataIndex]) throw new Error('external 7z property is not available')
  return dataVector[dataIndex]
}

function decodeUtf16LeNames(data, numFiles) {
  const names = []
  let start = 0
  for (let i = 0; i < numFiles; i++) {
    let end = start
    while (end + 1 < data.length && !(data[end] === 0 && data[end + 1] === 0)) {
      end += 2
    }
    if (end + 1 >= data.length) throw new Error('7z file name is not terminated')
    names.push(data.subarray(start, end).toString('utf16le'))
    start = end + 2
  }
  return names
}

function readFilesInfo(reader, streamsInfo, dataVector) {
  const numFiles = reader.readNum()
  const files = Array.from({ length: numFiles }, () => ({
    hasStream: true,
    isDir: false,
    size: 0,
    name: '',
  }))
  let emptyStreamVector = []
  let emptyFileVector = []
  for (;;) {
    const type = reader.readId()
    if (type === NID.END) break
    const size = reader.readNum()
    const propReader = new ByteReader(reader.readBytes(size))
    if (type === NID.EMPTY_STREAM) {
      emptyStreamVector = propReader.readBoolVector(numFiles)
    } else if (type === NID.EMPTY_FILE) {
      const count = emptyStreamVector.filter(Boolean).length
      emptyFileVector = propReader.readBoolVector(count)
    } else if (type === NID.NAME) {
      const names = decodeUtf16LeNames(readExternalDataProperty(propReader, dataVector), numFiles)
      for (let i = 0; i < numFiles; i++) {
        files[i].name = names[i]
      }
    }
  }

  let emptyIndex = 0
  let streamIndex = 0
  const unpackSizes = streamsInfo.subStreamsInfo ? streamsInfo.subStreamsInfo.unpackSizes : []
  for (let i = 0; i < numFiles; i++) {
    if (emptyStreamVector[i]) {
      files[i].hasStream = false
      files[i].isDir = !emptyFileVector[emptyIndex]
      emptyIndex++
    } else {
      files[i].hasStream = true
      files[i].isDir = false
      files[i].size = unpackSizes[streamIndex++] || 0
    }
  }
  return files
}

function parseHeaderBytes(buffer, dataVector = null) {
  const reader = new ByteReader(buffer)
  let type = reader.readId()
  if (type !== NID.HEADER) throw new Error('7z header is invalid')
  const result = {
    additionalStreamsInfo: null,
    mainStreamsInfo: null,
    files: [],
  }
  type = reader.readId()
  if (type === NID.ARCHIVE_PROPERTIES) {
    for (;;) {
      const propertyType = reader.readId()
      if (propertyType === NID.END) break
      reader.skip(reader.readNum())
    }
    type = reader.readId()
  }
  if (type === NID.ADDITIONAL_STREAMS_INFO) {
    result.additionalStreamsInfo = readStreamsInfo(reader)
    type = reader.readId()
  }
  if (type === NID.MAIN_STREAMS_INFO) {
    result.mainStreamsInfo = readStreamsInfo(reader)
    type = reader.readId()
  }
  if (type === NID.FILES_INFO) {
    result.files = readFilesInfo(reader, result.mainStreamsInfo || { subStreamsInfo: null }, dataVector)
    type = reader.readId()
  }
  if (type !== NID.END) throw new Error('7z header end marker not found')
  return result
}

function parseSevenZipAesCbcProperties(properties) {
  let cycles = 0
  let salt = Buffer.alloc(0)
  const iv = Buffer.alloc(AES_BLOCK_SIZE)
  if (!properties || properties.length === 0) {
    return { cycles, salt, iv }
  }
  const b0 = properties[0]
  cycles = b0 & 0x3f
  if ((b0 & 0xc0) === 0) {
    if (properties.length !== 1) throw new Error('7z AES-CBC properties are invalid')
    return { cycles, salt, iv }
  }
  if (properties.length <= 1) throw new Error('7z AES-CBC properties are invalid')
  const b1 = properties[1]
  const saltSize = ((b0 >> 7) & 1) + (b1 >> 4)
  const ivSize = ((b0 >> 6) & 1) + (b1 & 0x0f)
  if (properties.length !== 2 + saltSize + ivSize) throw new Error('7z AES-CBC properties are invalid')
  salt = properties.subarray(2, 2 + saltSize)
  properties.subarray(2 + saltSize, 2 + saltSize + ivSize).copy(iv, 0)
  if (cycles > 24 && cycles !== 0x3f) throw new Error('unsupported 7z AES-CBC cycles')
  return { cycles, salt, iv }
}

function deriveSevenZipAesCbcKey(password, salt, cycles) {
  const passwordHash = crypto.createHash('sha256').update(String(password || '')).digest('hex')
  const cacheKey = `${cycles}:${Buffer.from(salt || Buffer.alloc(0)).toString('hex')}:${passwordHash}`
  const cachedKey = derivedKeyCache.get(cacheKey)
  if (cachedKey) return Buffer.from(cachedKey)
  const passwordBytes = Buffer.from(String(password || ''), 'utf16le')
  const saltBytes = Buffer.from(salt || Buffer.alloc(0))
  let key
  if (cycles === 0x3f) {
    key = Buffer.alloc(32)
    Buffer.concat([saltBytes, passwordBytes]).copy(key)
  } else {
    const rounds = 1 << cycles
    const hash = crypto.createHash('sha256')
    const counter = Buffer.alloc(8)
    for (let i = 0; i < rounds; i++) {
      counter.writeUInt32LE(i >>> 0, 0)
      counter.writeUInt32LE(Math.floor(i / 0x100000000), 4)
      hash.update(saltBytes)
      hash.update(passwordBytes)
      hash.update(counter)
    }
    key = hash.digest()
  }
  if (derivedKeyCache.size >= MAX_DERIVED_KEY_CACHE_SIZE) {
    derivedKeyCache.delete(derivedKeyCache.keys().next().value)
  }
  derivedKeyCache.set(cacheKey, Buffer.from(key))
  return key
}

function createAesCbcDecipher(key, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  decipher.setAutoPadding(false)
  return decipher
}

function createAesCbcCipher(key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  cipher.setAutoPadding(false)
  return cipher
}

function decryptSevenZipAesCbcBytes(cipherBytes, password, aesInfo, ivOverride = null) {
  if (cipherBytes.length % AES_BLOCK_SIZE !== 0) {
    throw new Error('7z AES-CBC cipher range must be block aligned')
  }
  const key = deriveSevenZipAesCbcKey(password, aesInfo.salt, aesInfo.cycles)
  const decipher = createAesCbcDecipher(key, ivOverride || aesInfo.iv)
  return Buffer.concat([decipher.update(cipherBytes), decipher.final()])
}

function encryptSevenZipAesCbcBytes(plainBytes, password, aesInfo) {
  if (plainBytes.length % AES_BLOCK_SIZE !== 0) {
    throw new Error('7z AES-CBC plain bytes must be block aligned')
  }
  const key = deriveSevenZipAesCbcKey(password, aesInfo.salt, aesInfo.cycles)
  const cipher = createAesCbcCipher(key, aesInfo.iv)
  return Buffer.concat([cipher.update(plainBytes), cipher.final()])
}

function decodeFolderPackedBytes(packedBytes, folder, password) {
  let data = Buffer.from(packedBytes)
  const coders = folder.coders
  for (let i = 0; i < coders.length; i++) {
    const coder = coders[i]
    if (coder.method === METHOD_7Z_AES) {
      const aesInfo = parseSevenZipAesCbcProperties(coder.properties)
      data = decryptSevenZipAesCbcBytes(data, password, aesInfo)
    } else if (coder.method === METHOD_COPY) {
      data = Buffer.from(data)
    } else {
      throw new Error(`unsupported 7z method: ${coder.method}`)
    }
  }
  return data.subarray(0, getFolderUnpackSize(folder))
}

function validateSevenZipAesCbcFolder(folder, packedSize, plainSize) {
  const methods = folder.coders.map((coder) => coder.method)
  if (folder.packedStreams.length !== 1) throw new Error('7z AES-CBC playback supports one pack stream only')
  if (methods.length < 2 || !methods.includes(METHOD_COPY) || !methods.includes(METHOD_7Z_AES)) {
    throw new Error('7z AES-CBC playback requires Copy + 7zAES methods')
  }
  const firstUnsupported = methods.find((method) => method !== METHOD_COPY && method !== METHOD_7Z_AES)
  if (firstUnsupported) throw new Error(`unsupported 7z method: ${firstUnsupported}`)
  if (packedSize < plainSize) throw new Error('7z AES-CBC packed size is invalid')
  if (packedSize % AES_BLOCK_SIZE !== 0) throw new Error('7z AES-CBC packed size must be AES block aligned')
}

function getSevenZipAesCbcCoder(folder) {
  const coder = folder.coders.find((item) => item.method === METHOD_7Z_AES)
  if (!coder) throw new Error('7z AES-CBC coder not found')
  return coder
}

async function decodeEncodedHeader(type, reader, readRange, password) {
  if (type !== NID.ENCODED_HEADER) return null
  const streamsInfo = readStreamsInfo(reader)
  const packInfo = streamsInfo.packInfo
  if (!packInfo || packInfo.numPackStreams !== 1 || streamsInfo.folders.length !== 1) {
    throw new Error('unsupported 7z encoded header layout')
  }
  const folder = streamsInfo.folders[0]
  const packedSize = packInfo.packSizes[0]
  const packedOffset = SEVEN_ZIP_START_POSITION_AFTER_HEADER + packInfo.packPos
  const packedBytes = await readRange(packedOffset, packedSize)
  const headerBytes = decodeFolderPackedBytes(packedBytes, folder, password)
  return parseHeaderBytes(headerBytes)
}

function getMainFolderInfo(header) {
  const streamsInfo = header.mainStreamsInfo
  if (!streamsInfo || !streamsInfo.packInfo || !streamsInfo.folders.length) {
    throw new Error('7z main stream info not found')
  }
  if (streamsInfo.packInfo.numPackStreams !== 1 || streamsInfo.folders.length !== 1) {
    throw new Error('7z AES-CBC playback supports single-file non-solid archives only')
  }
  const filesWithStream = header.files.filter((file) => file.hasStream && !file.isDir)
  if (filesWithStream.length !== 1 || header.files.length !== 1) {
    throw new Error('7z AES-CBC playback supports single-file archives only')
  }
  const folder = streamsInfo.folders[0]
  const plainSize = filesWithStream[0].size
  const packedSize = streamsInfo.packInfo.packSizes[0]
  validateSevenZipAesCbcFolder(folder, packedSize, plainSize)
  return {
    folder,
    file: filesWithStream[0],
    packInfo: streamsInfo.packInfo,
    packedSize,
    plainSize,
  }
}

export function isSevenZipAesCbcEncType(encType) {
  return encType === SEVEN_ZIP_AES_CBC_ENC_TYPE
}

export function isSevenZipAesCbcFileName(fileName = '') {
  return String(fileName || '').toLowerCase().endsWith('.7z')
}

export function getSevenZipAesCbcPackageName(fileName) {
  const normalizedName = normalizeName(fileName)
  return isSevenZipAesCbcFileName(normalizedName) ? normalizedName : `${normalizedName}.7z`
}

export function buildSevenZipAesCbcInfo(plainSize, options = {}) {
  const layout = buildSevenZipAesCbcLayout({
    plainSize: Number(plainSize) || 0,
    originalName: options.originalName || options.origName || 'payload.bin',
    innerName: options.innerName,
    iv: options.iv ? Buffer.from(options.iv) : Buffer.alloc(AES_BLOCK_SIZE),
  })
  return {
    encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
    innerName: layout.innerName,
    packageSize: layout.packageSize,
    totalSize: layout.packageSize,
    plainSize: layout.plainSize,
    payloadOffset: layout.payloadOffset,
    packedSize: layout.packedSize,
    payloadSize: layout.payloadSize,
    method: 'copy+7zaes',
    solid: false,
    cycles: layout.cycles,
    salt: Buffer.alloc(0),
    iv: layout.iv,
  }
}

export async function parseSevenZipAesCbcInfoFromReader(readRange, totalSize, password) {
  const signatureHeader = await readRange(0, SIGNATURE_HEADER_SIZE)
  if (signatureHeader.length < SIGNATURE_HEADER_SIZE || !signatureHeader.subarray(0, 6).equals(SIGNATURE)) {
    throw new Error('7z signature not found')
  }
  const nextHeaderOffset = readUInt64LE(signatureHeader, 12)
  const nextHeaderSize = readUInt64LE(signatureHeader, 20)
  if (nextHeaderSize <= 0) throw new Error('7z header is empty')
  const nextHeaderStart = SEVEN_ZIP_START_POSITION_AFTER_HEADER + nextHeaderOffset
  const nextHeader = await readRange(nextHeaderStart, nextHeaderSize)
  const reader = new ByteReader(nextHeader)
  const type = reader.readId()
  let header
  if (type === NID.HEADER) {
    header = parseHeaderBytes(nextHeader)
  } else if (type === NID.ENCODED_HEADER) {
    header = await decodeEncodedHeader(type, reader, readRange, password)
  } else {
    throw new Error('7z header type is invalid')
  }

  const { folder, file, packInfo, packedSize, plainSize } = getMainFolderInfo(header)
  const aesCoder = getSevenZipAesCbcCoder(folder)
  const aesInfo = parseSevenZipAesCbcProperties(aesCoder.properties)
  const payloadOffset = SEVEN_ZIP_START_POSITION_AFTER_HEADER + packInfo.packPos
  return {
    encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
    innerName: normalizeName(file.name),
    packageSize: totalSize,
    totalSize,
    plainSize,
    payloadOffset,
    packedSize,
    payloadSize: plainSize,
    method: 'copy+7zaes',
    solid: false,
    cycles: aesInfo.cycles,
    salt: aesInfo.salt,
    iv: aesInfo.iv,
  }
}

export async function parseSevenZipAesCbcInfoFromFile(filePath, password) {
  const fs = await import('fs')
  const stat = await fs.promises.stat(filePath)
  const handle = await fs.promises.open(filePath, 'r')
  try {
    const readRange = async (start, length) => {
      const buffer = Buffer.alloc(length)
      const result = await handle.read(buffer, 0, length, start)
      return buffer.subarray(0, result.bytesRead)
    }
    return await parseSevenZipAesCbcInfoFromReader(readRange, stat.size, password)
  } finally {
    await handle.close()
  }
}

export async function parseSevenZipAesCbcInfoFromRemote(urlAddr, headers = {}, candidateSize = 0, password, options = {}) {
  const totalSize = await getRemoteSize(urlAddr, headers, Number(candidateSize) || 0, options)
  const readRange = (start, length) => readRemoteRange(urlAddr, headers, start, length, options)
  return await parseSevenZipAesCbcInfoFromReader(readRange, totalSize, password)
}

export function prepareSevenZipAesCbcDownloadRequest(request, sevenZipAesCbcInfo, clientRangeHeader) {
  const plainRange = parseRange(clientRangeHeader, sevenZipAesCbcInfo.plainSize)
  const blockStart = Math.floor(plainRange.start / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
  const blockEnd = Math.ceil((plainRange.end + 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - 1
  const cipherStart = blockStart === 0 ? sevenZipAesCbcInfo.payloadOffset : sevenZipAesCbcInfo.payloadOffset + blockStart - AES_BLOCK_SIZE
  const cipherEnd = sevenZipAesCbcInfo.payloadOffset + blockEnd
  request.sevenZipAesCbcInfo = sevenZipAesCbcInfo
  request.sevenZipAesCbcPlainRange = plainRange
  request.sevenZipAesCbcBlockStart = blockStart
  request.sevenZipAesCbcCipherStart = cipherStart
  request.sevenZipAesCbcPackageRange = { start: cipherStart, end: cipherEnd }
  request.sevenZipAesCbcDropBytes = plainRange.start - blockStart
  request.sevenZipAesCbcTakeBytes = plainRange.end - plainRange.start + 1
  request.sevenZipAesCbcUsesPreviousCipherBlock = blockStart > 0
  delete request.headers['accept-encoding']
  if (request.method.toLocaleUpperCase() !== 'HEAD') {
    request.headers.range = `bytes=${cipherStart}-${cipherEnd}`
  }
  return plainRange
}

export function applySevenZipAesCbcResponseHeaders(response, request) {
  const { sevenZipAesCbcInfo, sevenZipAesCbcPlainRange } = request
  if (!sevenZipAesCbcInfo || !sevenZipAesCbcPlainRange) return
  if (response.statusCode >= 300 && response.statusCode < 400) return
  if (sevenZipAesCbcPlainRange.hasRange) {
    response.statusCode = 206
    response.setHeader(
      'content-range',
      `bytes ${sevenZipAesCbcPlainRange.start}-${sevenZipAesCbcPlainRange.end}/${sevenZipAesCbcInfo.plainSize}`
    )
  } else if (response.statusCode < 300) {
    response.statusCode = 200
    response.removeHeader('content-range')
  }
  response.setHeader('accept-ranges', 'bytes')
  response.setHeader(
    'content-length',
    String(Math.max(0, sevenZipAesCbcPlainRange.end - sevenZipAesCbcPlainRange.start + 1))
  )
  response.setHeader('content-type', getMimeByName(request.sevenZipAesCbcVirtualName || sevenZipAesCbcInfo.innerName || request.url))
  response.removeHeader('content-encoding')
  response.removeHeader('transfer-encoding')
}

export function decryptSevenZipAesCbcRange(cipherBytes, sevenZipAesCbcInfo, plainStart, plainEnd, password) {
  const blockStart = Math.floor(plainStart / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
  const drop = plainStart - blockStart
  let bytesToDecrypt = Buffer.from(cipherBytes)
  let iv = sevenZipAesCbcInfo.iv
  if (blockStart > 0) {
    if (bytesToDecrypt.length < AES_BLOCK_SIZE) throw new Error('7z AES-CBC range is missing previous cipher block')
    iv = bytesToDecrypt.subarray(0, AES_BLOCK_SIZE)
    bytesToDecrypt = bytesToDecrypt.subarray(AES_BLOCK_SIZE)
  }
  const decrypted = decryptSevenZipAesCbcBytes(bytesToDecrypt, password, sevenZipAesCbcInfo, iv)
  return decrypted.subarray(drop, drop + (plainEnd - plainStart + 1))
}

export function serializeSevenZipAesCbcInfo(sevenZipAesCbcInfo) {
  if (!sevenZipAesCbcInfo) return null
  return {
    ...sevenZipAesCbcInfo,
    encType: SEVEN_ZIP_AES_CBC_ENC_TYPE,
    salt: sevenZipAesCbcInfo.salt ? Buffer.from(sevenZipAesCbcInfo.salt).toString('hex') : undefined,
    iv: sevenZipAesCbcInfo.iv ? Buffer.from(sevenZipAesCbcInfo.iv).toString('hex') : undefined,
  }
}

export function deserializeSevenZipAesCbcInfo(sevenZipAesCbcInfo) {
  if (!sevenZipAesCbcInfo || !isSevenZipAesCbcEncType(sevenZipAesCbcInfo.encType)) return null
  return {
    ...sevenZipAesCbcInfo,
    salt: Object.prototype.hasOwnProperty.call(sevenZipAesCbcInfo, 'salt')
      ? Buffer.from(sevenZipAesCbcInfo.salt || '', 'hex')
      : undefined,
    iv: Object.prototype.hasOwnProperty.call(sevenZipAesCbcInfo, 'iv')
      ? Buffer.from(sevenZipAesCbcInfo.iv || '', 'hex')
      : undefined,
  }
}

class SevenZipAesCbc {
  constructor(password, fileSize = 0, options = {}) {
    this.password = password
    this.plainSize = Number(fileSize) || 0
    this.options = options || {}
    this.sevenZipAesCbcInfo = this.options.sevenZipAesCbcInfo || null
    this.passwdOutward = deriveOutwardPassword(password)
    this.innerName = this.options.innerName || getInnerName(this.options.originalName || this.options.origName || 'payload.bin')
    this.originalName = normalizeName(this.options.originalName || this.options.origName || this.innerName)
    this.iv = this.sevenZipAesCbcInfo && this.sevenZipAesCbcInfo.iv ? Buffer.from(this.sevenZipAesCbcInfo.iv) : crypto.randomBytes(AES_BLOCK_SIZE)
    this.headerIv = this.options.headerIv ? Buffer.from(this.options.headerIv) : crypto.randomBytes(AES_BLOCK_SIZE)
    this.position = 0
  }

  static packageSize(plainSize, options = {}) {
    return buildSevenZipAesCbcLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || 'payload.bin',
      innerName: options.innerName,
      iv: Buffer.alloc(AES_BLOCK_SIZE),
      headerIv: Buffer.alloc(AES_BLOCK_SIZE),
    }).packageSize
  }

  static layout(plainSize, options = {}) {
    return buildSevenZipAesCbcLayout({
      plainSize: Number(plainSize) || 0,
      originalName: options.originalName || options.origName || 'payload.bin',
      innerName: options.innerName,
      iv: options.iv ? Buffer.from(options.iv) : Buffer.alloc(AES_BLOCK_SIZE),
      headerIv: options.headerIv ? Buffer.from(options.headerIv) : Buffer.alloc(AES_BLOCK_SIZE),
    })
  }

  async setPositionAsync(position = 0) {
    this.position = Number(position) || 0
  }

  encryptTransform() {
    const layout = buildSevenZipAesCbcLayout({
      plainSize: this.plainSize,
      originalName: this.originalName,
      innerName: this.innerName,
      iv: this.iv,
      headerIv: this.headerIv,
    })
    const key = deriveSevenZipAesCbcKey(this.password, Buffer.alloc(0), SEVEN_ZIP_AES_CBC_CYCLES)
    const cipher = createAesCbcCipher(key, this.iv)
    let started = false
    let written = 0
    const self = this

    return new Transform({
      transform(chunk, encoding, next) {
        try {
          if (!started) {
            this.push(layout.signatureHeader)
            started = true
          }
          written += chunk.length
          const encrypted = cipher.update(chunk)
          if (encrypted.length) {
            this.push(encrypted)
          }
          next()
        } catch (e) {
          next(e)
        }
      },
      flush(next) {
        try {
          if (!started) {
            this.push(layout.signatureHeader)
          }
          if (written !== self.plainSize) {
            this.destroy(new Error('7z AES-CBC upload size changed while streaming'))
            return
          }
          const paddingSize = layout.packedSize - written
          if (paddingSize > 0) {
            const encryptedPadding = cipher.update(Buffer.alloc(paddingSize))
            if (encryptedPadding.length) {
              this.push(encryptedPadding)
            }
          }
          const final = cipher.final()
          if (final.length) {
            this.push(final)
          }
          const headerPaddingSize = layout.encodedHeaderPackedSize - layout.innerHeader.length
          const headerPlain = headerPaddingSize > 0
            ? Buffer.concat([layout.innerHeader, Buffer.alloc(headerPaddingSize)])
            : layout.innerHeader
          this.push(encryptSevenZipAesCbcBytes(headerPlain, self.password, {
            salt: Buffer.alloc(0),
            cycles: SEVEN_ZIP_AES_CBC_CYCLES,
            iv: layout.encodedHeaderIv,
          }))
          this.push(layout.header)
          next()
        } catch (e) {
          next(e)
        }
      },
    })
  }

  decryptTransform() {
    const self = this
    const info = this.sevenZipAesCbcInfo
    if (!info) throw new Error('7z AES-CBC info is required')
    const plainRange = this.options.plainRange || {
      start: this.position,
      end: this.position + Math.max(0, this.plainSize - 1),
    }
    const blockStart = Math.floor(plainRange.start / AES_BLOCK_SIZE) * AES_BLOCK_SIZE
    const usesPreviousCipherBlock = blockStart > 0
    const key = deriveSevenZipAesCbcKey(this.password, info.salt, info.cycles)
    let decipher = usesPreviousCipherBlock ? null : createAesCbcDecipher(key, info.iv)
    let previousCipherBlock = Buffer.alloc(0)
    let dropBytes = plainRange.start - blockStart
    let takeBytes = plainRange.end - plainRange.start + 1
    let written = 0

    function pushPlain(stream, plain) {
      if (!plain.length || written >= takeBytes) return
      let output = plain
      if (dropBytes > 0) {
        const drop = Math.min(dropBytes, output.length)
        output = output.subarray(drop)
        dropBytes -= drop
      }
      if (!output.length || written >= takeBytes) return
      const take = Math.min(output.length, takeBytes - written)
      if (take > 0) {
        stream.push(output.subarray(0, take))
        written += take
      }
    }

    function updateCipher(stream, chunk) {
      if (!chunk.length) return
      if (!decipher) {
        const need = AES_BLOCK_SIZE - previousCipherBlock.length
        previousCipherBlock = Buffer.concat([previousCipherBlock, chunk.subarray(0, need)])
        chunk = chunk.subarray(need)
        if (previousCipherBlock.length === AES_BLOCK_SIZE) {
          decipher = createAesCbcDecipher(key, previousCipherBlock)
        }
      }
      if (decipher && chunk.length) {
        pushPlain(stream, decipher.update(chunk))
      }
    }

    return new Transform({
      transform(chunk, encoding, next) {
        try {
          updateCipher(this, chunk)
          next()
        } catch (e) {
          next(e)
        }
      },
      flush(next) {
        try {
          if (!decipher) {
            throw new Error('7z AES-CBC range is missing previous cipher block')
          }
          pushPlain(this, decipher.final())
          if (written !== takeBytes) {
            throw new Error('7z AES-CBC range ended before expected plaintext bytes')
          }
          next()
        } catch (e) {
          next(e)
        }
      },
    })
  }
}

export default SevenZipAesCbc
