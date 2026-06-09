import assert from 'assert'

import {
  cacheZipInfo,
  getCachedZipInfo,
  zipInfoCacheKey,
  zipInfoValidator,
} from '@/dao/zipInfoDao'
import levelDB from '@/utils/levelDB'

const passwdInfo = {
  encType: 'zip',
  zipMode: 'winzip-aes',
  password: 'admin123',
}

async function main() {
  await levelDB.load()
  assert.deepStrictEqual(zipInfoValidator(null, 4096), { size: 4096, modified: '' })
  const realPath = `/会员/压缩包播放测试/cache-test-${Date.now()}.mp4.zip`
  const validator = zipInfoValidator({ size: 123456, modified: '2026-06-08T00:00:00Z' })
  const zipInfo = {
    encType: 'zip',
    zipMode: 'winzip-aes',
    plainSize: 1000,
    payloadOffset: 88,
    compressedSize: 1028,
    salt: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    nonce: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    meta: Buffer.from('abcd', 'hex'),
    checkpoints: [{ offset: 0, state: { key0: 1, key1: 2, key2: 3 } }],
  }

  assert.strictEqual(await getCachedZipInfo({ realPath, passwdInfo, validator }), null)
  await cacheZipInfo({ realPath, passwdInfo, validator, zipInfo })

  const cached = await getCachedZipInfo({ realPath, passwdInfo, validator })
  assert.strictEqual(cached.zipMode, zipInfo.zipMode)
  assert.strictEqual(cached.payloadOffset, zipInfo.payloadOffset)
  assert.ok(Buffer.isBuffer(cached.salt))
  assert.deepStrictEqual(cached.salt, zipInfo.salt)
  assert.deepStrictEqual(cached.checkpoints, zipInfo.checkpoints)

  const stale = await getCachedZipInfo({
    realPath,
    passwdInfo,
    validator: zipInfoValidator({ size: 123457, modified: '2026-06-08T00:00:00Z' }),
  })
  assert.strictEqual(stale, null)

  await levelDB.datastore.removeMany({ key: zipInfoCacheKey({ realPath, passwdInfo }) })
  console.log('zipInfoDaoTest ok')
  process.exit(0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
