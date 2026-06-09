import assert from 'assert'
import crypto from 'crypto'
import childProcess from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { Readable, Writable } from 'stream'
import { finished } from 'stream/promises'

import FlowEnc from '@/utils/flowEnc'
import ZipPackageEnc from '@/utils/zipPackageEnc'
import {
  ZIP_MODE_COMPATIBLE,
  ZIP_MODE_FAKE,
  ZIP_MODE_WINZIP_AES,
  parseZipInfoFromFile,
  prepareZipDownloadRequest,
} from '@/utils/zipPackageEnc'
import {
  convertRealName,
  convertShowName,
  decodeZipStorageName,
  encodeZipStorageName,
  inferAListType,
} from '@/utils/commonUtil'

const password = 'admin123'

async function encryptToFile(plain, filePath, zipMode, originalName) {
  const flowEnc = new FlowEnc(password, 'zip', plain.length, { zipMode, originalName })
  const write = fs.createWriteStream(filePath)
  Readable.from([plain]).pipe(flowEnc.encryptTransform()).pipe(write)
  await finished(write)
}

function readFileRange(filePath, start, end) {
  return fs.readFileSync(filePath).subarray(start, end + 1)
}

function hasExtraField(extra, fieldId) {
  let offset = 0
  while (offset + 4 <= extra.length) {
    const id = extra.readUInt16LE(offset)
    const size = extra.readUInt16LE(offset + 2)
    if (offset + 4 + size > extra.length) break
    if (id === fieldId) return true
    offset += 4 + size
  }
  return false
}

function readFirstLocalExtra(filePath) {
  const fd = fs.openSync(filePath, 'r')
  try {
    const fixed = Buffer.alloc(30)
    fs.readSync(fd, fixed, 0, fixed.length, 0)
    assert.strictEqual(fixed.readUInt32LE(0), 0x04034b50)
    const nameLen = fixed.readUInt16LE(26)
    const extraLen = fixed.readUInt16LE(28)
    const extra = Buffer.alloc(extraLen)
    fs.readSync(fd, extra, 0, extraLen, 30 + nameLen)
    return extra
  } finally {
    fs.closeSync(fd)
  }
}

async function decryptRange(filePath, rangeHeader) {
  const zipInfo = await parseZipInfoFromFile(filePath)
  const request = { method: 'GET', headers: {}, zipVirtualName: '测试 视频.final.mp4' }
  prepareZipDownloadRequest(request, zipInfo, rangeHeader)
  const rangeText = request.headers.range.replace('bytes=', '')
  const [remoteStart, remoteEnd] = rangeText.split('-').map((item) => Number(item))
  const encrypted = readFileRange(filePath, remoteStart, remoteEnd)
  const flowEnc = new FlowEnc(password, 'zip', zipInfo.plainSize, { zipInfo })
  await flowEnc.setPosition(request.zipPlainRange.start)
  const chunks = []
  const write = new Writable({
    write(chunk, enc, next) {
      chunks.push(chunk)
      next()
    },
  })
  Readable.from([encrypted]).pipe(flowEnc.decryptTransform()).pipe(write)
  await finished(write)
  return Buffer.concat(chunks)
}

async function verifyMode(zipMode) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-zip-test-'))
  const originalName = '测试 视频.final.mp4'
  const plain = Buffer.concat([
    Buffer.from('ftyp'),
    crypto.randomBytes(256 * 1024 + 333),
    Buffer.from('tail-marker'),
  ])
  const zipPath = path.join(tempDir, `${zipMode}.zip`)
  await encryptToFile(plain, zipPath, zipMode, originalName)
  fs.writeFileSync(path.join(tempDir, 'plain.bin'), plain)
  const zipInfo = await parseZipInfoFromFile(zipPath)

  assert.strictEqual(zipInfo.plainSize, plain.length)
  assert.strictEqual(zipInfo.zipMode, zipMode)
  assert.ok(zipInfo.payloadOffset > 30, 'payload must start after ZIP headers')
  assert.strictEqual(
    fs.statSync(zipPath).size,
    ZipPackageEnc.packageSize(plain.length, { originalName, zipMode, password }),
    `${zipMode} package size`
  )

  const ranges = [
    [0, 63],
    [7, 4095],
    [65531, 65531 + 8192],
    [Math.max(0, Math.floor(plain.length / 2) - 17), Math.min(plain.length - 1, Math.floor(plain.length / 2) + 10000)],
    [Math.max(0, plain.length - 9000), plain.length - 1],
  ]
  for (const [start, end] of ranges) {
    const actual = await decryptRange(zipPath, `bytes=${start}-${end}`)
    assert.deepStrictEqual(actual, plain.subarray(start, end + 1), `${zipMode} range ${start}-${end}`)
  }

  const head = await decryptRange(zipPath, 'bytes=0-3')
  assert.deepStrictEqual(head, plain.subarray(0, 4))
  assert.notDeepStrictEqual(head, Buffer.from([0x50, 0x4b, 0x03, 0x04]), 'player output must not include ZIP local header')

  if (zipMode === ZIP_MODE_COMPATIBLE) {
    const verifyScript = [
      'import pathlib, sys, zipfile',
      'zip_path = pathlib.Path(sys.argv[1])',
      'plain_path = pathlib.Path(sys.argv[2])',
      'with zipfile.ZipFile(zip_path) as zf:',
      "    data = zf.read(zf.namelist()[0], pwd=b'admin123')",
      'assert data == plain_path.read_bytes()',
    ].join('\n')
    childProcess.execFileSync('python', ['-c', verifyScript, zipPath, path.join(tempDir, 'plain.bin')], { stdio: 'pipe' })
  }

  if (zipMode === ZIP_MODE_WINZIP_AES) {
    const zipBytes = fs.readFileSync(zipPath)
    const namedInfo = await parseZipInfoFromFile(zipPath, { password })
    assert.strictEqual(namedInfo.origName, originalName)
    assert.ok(!zipBytes.includes(Buffer.from(originalName, 'utf8')), 'original name must stay encrypted')
    assert.strictEqual(zipInfo.compressedSize, plain.length + 28)
    assert.strictEqual(zipInfo.authSize, 10)
    const header = zipBytes.subarray(0, zipInfo.headerSize)
    assert.strictEqual(header.readUInt16LE(8), 99)
    assert.ok(header.includes(Buffer.from([0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x03, 0x00, 0x00])))
    const verifyScript = [
      'import pathlib, sys, pyzipper',
      'zip_path = pathlib.Path(sys.argv[1])',
      'plain_path = pathlib.Path(sys.argv[2])',
      'with pyzipper.AESZipFile(zip_path) as zf:',
      "    zf.setpassword(b'admin123')",
      '    names = zf.namelist()',
      "    assert names == ['payload.mp4'], names",
      '    data = zf.read(names[0])',
      'assert data == plain_path.read_bytes()',
    ].join('\n')
    childProcess.execFileSync('python', ['-c', verifyScript, zipPath, path.join(tempDir, 'plain.bin')], { stdio: 'pipe' })
  }
}

async function verifyNativeWinZipAesStore() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-native-aes-test-'))
  const originalName = 'external-tool.mp4'
  const plain = Buffer.concat([
    Buffer.from('ftypisom'),
    crypto.randomBytes(384 * 1024 + 91),
    Buffer.from('native-winzip-aes-tail'),
  ])
  const plainPath = path.join(tempDir, originalName)
  const zipPath = path.join(tempDir, 'native-winzip-aes-store.zip')
  fs.writeFileSync(plainPath, plain)

  const createScript = [
    'import pathlib, sys, zipfile, pyzipper',
    'plain_path = pathlib.Path(sys.argv[1])',
    'zip_path = pathlib.Path(sys.argv[2])',
    'with pyzipper.AESZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:',
    "    zf.setpassword(b'admin123')",
    '    zf.setencryption(pyzipper.WZ_AES, nbits=256)',
    '    zf.write(plain_path, arcname=plain_path.name)',
  ].join('\n')
  childProcess.execFileSync('python', ['-c', createScript, plainPath, zipPath], { stdio: 'pipe' })

  assert.ok(!hasExtraField(readFirstLocalExtra(zipPath), 0x5a46), 'native WinZip AES sample must not contain custom FZ extra field')

  const zipInfo = await parseZipInfoFromFile(zipPath, { password })
  assert.strictEqual(zipInfo.zipMode, ZIP_MODE_WINZIP_AES)
  assert.strictEqual(zipInfo.innerName, originalName)
  assert.strictEqual(zipInfo.origName, null)
  assert.strictEqual(zipInfo.plainSize, plain.length)
  assert.strictEqual(zipInfo.winZipAes.actualMethod, 0)
  assert.strictEqual(zipInfo.authSize, 10)
  assert.ok(Buffer.isBuffer(zipInfo.salt))
  assert.strictEqual(zipInfo.salt.length, 16)
  assert.strictEqual(zipInfo.compressedSize, plain.length + 28)

  const ranges = [
    [0, 63],
    [7, 4095],
    [Math.floor(plain.length / 2) - 13, Math.floor(plain.length / 2) + 1024],
    [plain.length - 2048, plain.length - 1],
  ]
  for (const [start, end] of ranges) {
    const actual = await decryptRange(zipPath, `bytes=${start}-${end}`)
    assert.deepStrictEqual(actual, plain.subarray(start, end + 1), `native winzip aes range ${start}-${end}`)
  }
}

async function verifyNames() {
  const names = ['测试 视频.final.mp4', 'a b.c.d.mkv', 'noext', '普通.zip']
  for (const name of names) {
    const real = encodeZipStorageName(password, 'zip', name)
    assert.ok(real.endsWith(`${path.extname(name)}.zip`), real)
    assert.strictEqual(decodeZipStorageName(password, 'zip', real), name)
    assert.strictEqual(convertRealName(password, 'zip', name), real)
    assert.strictEqual(convertShowName(password, 'zip', real), name)
  }
  assert.strictEqual(decodeZipStorageName(password, 'zip', 'ordinary.zip'), null)
  assert.strictEqual(convertShowName(password, 'zip', 'ordinary.zip'), 'ordinary.zip')
  assert.strictEqual(inferAListType('demo.mp4'), 2)
  assert.strictEqual(inferAListType('demo.mp4.zip'), 0)
}

async function main() {
  await verifyNames()
  await verifyMode(ZIP_MODE_COMPATIBLE)
  await verifyMode(ZIP_MODE_WINZIP_AES)
  await verifyMode(ZIP_MODE_FAKE)
  await verifyNativeWinZipAesStore()
  console.log('zipPackageEncTest ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
