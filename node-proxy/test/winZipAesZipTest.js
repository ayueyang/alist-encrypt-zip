import assert from 'assert'
import crypto from 'crypto'
import childProcess from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { pipeline } from 'stream/promises'
import WinZipAesZip from '../src/utils/winZipAesZip'
import {
  convertRealName,
  convertShowName,
  getAListFileTypeByName,
  isEncryptedZipName,
  isRawZipName,
} from '../src/utils/commonUtil'
import {
  isWinZipAesEncType,
  parseManagedWinZipAesZipInfoFromFile,
  parseWinZipAesZipInfoFromFile,
  prepareWinZipAesDownloadRequest,
  ZIP_AES_ENC_TYPE,
} from '../src/utils/winZipAesZip'
import {
  isUsableWinZipAesZipInfoCache,
  isUsableWinZipAesZipNegativeCache,
} from '../src/utils/winZipAesZipCache'

const password = 'admin123'

function readFileRange(filePath, start, end) {
  const fd = fs.openSync(filePath, 'r')
  try {
    const length = end - start + 1
    const buffer = Buffer.alloc(length)
    const bytesRead = fs.readSync(fd, buffer, 0, length, start)
    return buffer.subarray(0, bytesRead)
  } finally {
    fs.closeSync(fd)
  }
}

async function createZip(plain, originalName = 'video.final.mp4') {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-wz-aes-'))
  const plainPath = path.join(tempDir, originalName)
  const zipPath = path.join(tempDir, `${originalName}.zip`)
  fs.writeFileSync(plainPath, plain)
  const zipEnc = new WinZipAesZip(password, plain.length, { originalName })
  await pipeline(fs.createReadStream(plainPath), zipEnc.encryptTransform(), fs.createWriteStream(zipPath))
  return { tempDir, plainPath, zipPath }
}

function createExternalZip(plain, originalName = 'external.video.mp4') {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alist-wz-aes-external-'))
  const plainPath = path.join(tempDir, originalName)
  const zipPath = path.join(tempDir, `${originalName}.zip`)
  fs.writeFileSync(plainPath, plain)
  const pyCreate = [
    'import pathlib, pyzipper, sys',
    'plain_path = pathlib.Path(sys.argv[1])',
    'zip_path = pathlib.Path(sys.argv[2])',
    'with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as zf:',
    "    zf.setpassword(b'admin123')",
    '    zf.setencryption(pyzipper.WZ_AES, nbits=256)',
    '    zf.write(plain_path, arcname=plain_path.name)',
  ].join('\n')
  childProcess.execFileSync('python', ['-c', pyCreate, plainPath, zipPath])
  return { tempDir, plainPath, zipPath }
}

async function decryptRange(zipPath, rangeHeader) {
  const zipInfo = await parseWinZipAesZipInfoFromFile(zipPath)
  const request = { method: 'GET', headers: {}, url: '/video.final.mp4', zipVirtualName: 'video.final.mp4' }
  prepareWinZipAesDownloadRequest(request, zipInfo, rangeHeader)
  const encrypted = readFileRange(zipPath, request.zipPackageRange.start, request.zipPackageRange.end)
  const zipEnc = new WinZipAesZip(password, zipInfo.plainSize, { zipInfo })
  await zipEnc.setPositionAsync(request.zipCipherStart)
  const chunks = []
  await pipeline(
    async function* () {
      yield encrypted
    },
    zipEnc.decryptTransform(),
    async function* (source) {
      for await (const chunk of source) {
        chunks.push(chunk)
      }
    }
  )
  return Buffer.concat(chunks)
}

async function assertRanges(zipPath, plain) {
  const full = await decryptRange(zipPath)
  assert.deepStrictEqual(full, plain)

  const suffix = await decryptRange(zipPath, 'bytes=-1024')
  assert.deepStrictEqual(suffix, plain.subarray(plain.length - 1024))

  const ranges = [
    [0, 63],
    [7, 4095],
    [Math.floor(plain.length / 2) - 13, Math.floor(plain.length / 2) + 1024],
    [plain.length - 2048, plain.length - 1],
  ]
  for (const [start, end] of ranges) {
    const actual = await decryptRange(zipPath, `bytes=${start}-${end}`)
    assert.deepStrictEqual(actual, plain.subarray(start, end + 1), `range ${start}-${end}`)
  }
}

async function main() {
  assert.ok(isWinZipAesEncType(ZIP_AES_ENC_TYPE))
  const encryptedName = convertRealName(password, ZIP_AES_ENC_TYPE, '电影.final 4k.mp4')
  assert.ok(encryptedName.endsWith('.zip'))
  assert.ok(!encryptedName.endsWith('.mp4.zip'))
  assert.strictEqual(convertShowName(password, ZIP_AES_ENC_TYPE, encryptedName), '电影.final 4k.mp4')
  assert.ok(isEncryptedZipName(password, ZIP_AES_ENC_TYPE, encryptedName))
  assert.ok(!isRawZipName(password, ZIP_AES_ENC_TYPE, encryptedName))
  assert.ok(isRawZipName(password, ZIP_AES_ENC_TYPE, 'abc.zip'))
  assert.ok(isRawZipName(password, ZIP_AES_ENC_TYPE, 'abc.mp4.zip'))
  assert.strictEqual(getAListFileTypeByName('电影.final 4k.mp4'), 2)
  assert.ok(isUsableWinZipAesZipInfoCache({ size: 123, zipInfo: { encType: ZIP_AES_ENC_TYPE } }, 123))
  assert.ok(!isUsableWinZipAesZipInfoCache({ size: 124, zipInfo: { encType: ZIP_AES_ENC_TYPE } }, 123))
  assert.ok(isUsableWinZipAesZipNegativeCache({ size: 123, notPlayable: true }, 123))
  assert.ok(!isUsableWinZipAesZipNegativeCache({ size: 124, notPlayable: true }, 123))

  const plain = Buffer.concat([Buffer.from('ftypisom'), crypto.randomBytes(512 * 1024 + 37), Buffer.from('zip aes tail')])
  const { zipPath } = await createZip(plain)
  const zipInfo = await parseWinZipAesZipInfoFromFile(zipPath)
  const managedZipInfo = await parseManagedWinZipAesZipInfoFromFile(zipPath)

  assert.strictEqual(zipInfo.encType, ZIP_AES_ENC_TYPE)
  assert.strictEqual(zipInfo.innerName, 'payload.mp4')
  assert.strictEqual(zipInfo.plainSize, plain.length)
  assert.strictEqual(zipInfo.winZipAes.actualMethod, 0)
  assert.strictEqual(zipInfo.winZipAes.strength, 3)
  assert.strictEqual(zipInfo.salt.length, 16)
  assert.strictEqual(zipInfo.compressedSize, plain.length + 28)
  assert.strictEqual(managedZipInfo.innerName, zipInfo.innerName)
  assert.strictEqual(managedZipInfo.plainSize, zipInfo.plainSize)
  assert.strictEqual(managedZipInfo.payloadOffset, zipInfo.payloadOffset)
  assert.strictEqual(managedZipInfo.authTagOffset, zipInfo.authTagOffset)
  assert.deepStrictEqual(managedZipInfo.salt, zipInfo.salt)

  const pyCheck = [
    'import pathlib, pyzipper, sys',
    'zip_path = pathlib.Path(sys.argv[1])',
    'with pyzipper.AESZipFile(zip_path) as zf:',
    "    zf.setpassword(b'admin123')",
    '    names = zf.namelist()',
    '    assert names == ["payload.mp4"], names',
    '    data = zf.read(names[0])',
    '    sys.stdout.buffer.write(data)',
  ].join('\n')
  const unzipped = childProcess.execFileSync('python', ['-c', pyCheck, zipPath], { maxBuffer: plain.length + 1024 })
  assert.deepStrictEqual(unzipped, plain)

  await assertRanges(zipPath, plain)

  const externalPlain = Buffer.concat([Buffer.from('ftypmp42'), crypto.randomBytes(128 * 1024 + 31), Buffer.from('external zip aes')])
  const external = createExternalZip(externalPlain)
  const externalZipInfo = await parseWinZipAesZipInfoFromFile(external.zipPath)
  assert.strictEqual(externalZipInfo.innerName, 'external.video.mp4')
  assert.strictEqual(externalZipInfo.plainSize, externalPlain.length)
  assert.strictEqual(externalZipInfo.winZipAes.actualMethod, 0)
  await assertRanges(external.zipPath, externalPlain)

  console.log('winZipAesZipTest ok')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
