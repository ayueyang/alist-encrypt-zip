'use strict'
import fs from 'fs'
import path from 'path'

import mkdirp from 'mkdirp'
import FlowEnc from './flowEnc'
import { convertRealName, convertShowName, encodeName, decodeName } from './commonUtil'
import { isZipEncType, parseZipInfoFromFile } from './zipPackageEnc'

export function searchFile(filePath: string) {
  const fileArray: { size: number; filePath: string }[] = []
  const files = fs.readdirSync(filePath)
  files.forEach((child) => {
    const filePath2 = path.join(filePath, child),
      info = fs.statSync(filePath2)
    if (info.isDirectory()) {
      const deepArr = searchFile(filePath2)
      fileArray.push(...deepArr)
    } else {
      const data = { size: info.size, filePath: filePath2 }
      fileArray.push(data)
    }
  })
  return fileArray
}

// encrypt
export async function encryptFile(
  password: string,
  encType: string,
  enc: 'enc' | 'dec',
  encPath: string,
  outPath?: string,
  encName?: boolean | string,
  zipMode?: string
) {
  const start = Date.now()
  const interval = setInterval(() => {
    console.log(new Date(), 'waiting finish!!!')
  }, 2000)
  if (!path.isAbsolute(encPath)) {
    encPath = path.join(process.cwd(), encPath)
  }
  outPath = outPath || path.join(process.cwd(), 'outFile', Date.now().toString())
  console.log('you input:', password, encType, enc, encPath)
  if (!fs.existsSync(encPath)) {
    console.log('you input filePath is not exists ')
    return
  }
  // init outpath dir
  if (!fs.existsSync(outPath)) {
    mkdirp.sync(outPath)
  }
  // input file path
  const allFilePath = searchFile(encPath)
  const tempDir = path.join(outPath, '.temp')
  if (!fs.existsSync(tempDir)) {
    mkdirp.sync(tempDir)
  }
  let promiseArr = []
  for (const fileInfo of allFilePath) {
    const { filePath, size } = fileInfo
    let relativePath = filePath.substring(encPath.length)
    const fileName = path.basename(relativePath),
      ext = path.extname(relativePath),
      childPath = path.dirname(relativePath)
    if (enc === 'enc' && encName) {
      const newFileName = isZipEncType(encType) ? convertRealName(password, encType, fileName) : encodeName(password, encType, fileName) + ext
      relativePath = path.join(childPath, newFileName)
    }
    if (enc === 'dec' && encName) {
      const newFileName = isZipEncType(encType)
        ? convertShowName(password, encType, fileName)
        : decodeName(password, encType, ext !== '' ? fileName.substring(0, fileName.length - ext.length) : fileName)
      if (newFileName) {
        relativePath = path.join(childPath, newFileName)
      }
    }
    let zipInfo: any = null
    if (enc === 'dec' && isZipEncType(encType)) {
      zipInfo = await parseZipInfoFromFile(filePath)
      if (!encName && zipInfo.origName) {
        relativePath = path.join(childPath, zipInfo.origName)
      }
    }
    const outFilePath = path.join(outPath, relativePath)
    const outFilePathTemp = path.join(tempDir, relativePath)
    mkdirp.sync(path.dirname(outFilePathTemp))
    mkdirp.sync(path.dirname(outFilePath))
    // 开始加密
    if (size === 0) {
      continue
    }
    const flowOptions: any = { originalName: fileName, zipMode }
    let flowSize = size
    let readStart = 0
    if (enc === 'dec' && isZipEncType(encType)) {
      flowOptions.zipInfo = zipInfo
      flowSize = zipInfo.plainSize
      readStart = zipInfo.payloadOffset
    }
    const flowEnc = new FlowEnc(password, encType, flowSize, flowOptions)
    if (enc === 'dec' && isZipEncType(encType)) {
      await flowEnc.setPosition(0)
    }
    // console.log('@@outFilePath', outFilePath, encType, size)
    const writeStream = fs.createWriteStream(outFilePathTemp)
    const readStream = fs.createReadStream(filePath, isZipEncType(encType) && enc === 'dec' ? { start: readStart, end: readStart + flowSize - 1 } : undefined)
    const promise = new Promise<void>((resolve, reject) => {
      readStream.pipe(enc === 'enc' ? flowEnc.encryptTransform() : flowEnc.decryptTransform()).pipe(writeStream)
      readStream.on('end', () => {
        console.log('@@finish filePath', filePath, outFilePathTemp)
        fs.renameSync(outFilePathTemp, outFilePath)
        resolve()
      })
    })
    promiseArr.push(promise)
    if (promiseArr.length > 50) {
      await Promise.all(promiseArr)
      promiseArr = []
    }
  }
  await Promise.all(promiseArr)
  fs.rmSync(tempDir, { recursive: true })
  console.log('@@all finish', ((Date.now() - start) / 1000).toFixed(2) + 's')
  clearInterval(interval)
}

export function convertFile(...args: [password: string, encType: string, enc: 'enc' | 'dec', encPath: string, outPath?: string, encName?: string, zipMode?: string]) {
  const statTime = Date.now()
  if (args.length > 3) {
    encryptFile(...args).then(() => {
      console.log('all file finish enc!!! time:', Date.now() - statTime)
      process.exit(0)
    })
  } else {
    console.error('input error， example param:nodejs-linux passwd12345 rc4 enc ./myfolder /tmp/outPath encname  ')
    process.exit(1)
  }
}
