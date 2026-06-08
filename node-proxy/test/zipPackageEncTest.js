import assert from 'assert'
import crypto from 'crypto'
import childProcess from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { Readable, Writable } from 'stream'
import { finished } from 'stream/promises'

import FlowEnc from '@/utils/flowEnc'
import {
  ZIP_MODE_COMPATIBLE,
  ZIP_MODE_FAKE,
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
  const plain = Buffer.concat([
    Buffer.from('ftyp'),
    crypto.randomBytes(256 * 1024 + 333),
    Buffer.from('tail-marker'),
  ])
  const zipPath = path.join(tempDir, `${zipMode}.zip`)
  await encryptToFile(plain, zipPath, zipMode, '测试 视频.final.mp4')
  fs.writeFileSync(path.join(tempDir, 'plain.bin'), plain)
  const zipInfo = await parseZipInfoFromFile(zipPath)

  assert.strictEqual(zipInfo.plainSize, plain.length)
  assert.strictEqual(zipInfo.zipMode, zipMode)
  assert.ok(zipInfo.payloadOffset > 30, 'payload must start after ZIP headers')

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
  await verifyMode(ZIP_MODE_FAKE)
  console.log('zipPackageEncTest ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
