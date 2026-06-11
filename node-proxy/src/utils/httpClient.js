import http from 'http'
import https from 'node:https'
import crypto, { randomUUID } from 'crypto'
import levelDB from './levelDB'
import path from 'path'
import { decodeName } from './commonUtil'
// import { pathExec } from './commonUtil'
const Agent = http.Agent
const Agents = https.Agent

// 默认maxFreeSockets=256
const httpsAgent = new Agents({ keepAlive: true })
const httpAgent = new Agent({ keepAlive: true })

function prepareRedirectHeaders(request, redirectUrl) {
  const sourceUrl = new URL(request.urlAddr)
  const targetUrl = new URL(redirectUrl, sourceUrl)
  delete request.headers.host
  delete request.headers.Host
  if (sourceUrl.host !== targetUrl.host) {
    delete request.headers.authorization
    delete request.headers.Authorization
    delete request.headers.referer
    delete request.headers.Referer
  }
  if (targetUrl.hostname.includes('baidupcs.com')) {
    request.headers['User-Agent'] = 'pan.baidu.com'
  }
  request.urlAddr = targetUrl.toString()
}

export async function httpProxy(request, response, encryptTransform, decryptTransform) {
  const { method, headers, urlAddr, passwdInfo, url, fileSize } = request
  const reqId = randomUUID()
  console.log('@@request_info: ', reqId, method, urlAddr, headers, !!encryptTransform, !!decryptTransform)
  // 创建请求
  const options = {
    method,
    headers,
    agent: ~urlAddr.indexOf('https') ? httpsAgent : httpAgent,
    rejectUnauthorized: false,
  }
  const httpRequest = ~urlAddr.indexOf('https') ? https : http
  return new Promise((resolve, reject) => {
    // 处理重定向的请求，让下载的流量经过代理服务器
    const httpReq = httpRequest.request(urlAddr, options, async (httpResp) => {
      console.log('@@statusCode', reqId, httpResp.statusCode, httpResp.headers)
      const redirectLocation = httpResp.headers.location || ''
      if (
        request.followRemoteRedirect &&
        decryptTransform &&
        httpResp.statusCode >= 300 &&
        httpResp.statusCode < 400 &&
        redirectLocation &&
        (request.remoteRedirectCount || 0) < 5
      ) {
        httpResp.resume()
        request.remoteRedirectCount = (request.remoteRedirectCount || 0) + 1
        prepareRedirectHeaders(request, redirectLocation)
        httpProxy(request, response, null, decryptTransform).then(resolve).catch(reject)
        return
      }

      response.statusCode = httpResp.statusCode
      if (response.statusCode % 300 < 5) {
        // 可能出现304，redirectUrl = undefined
        const redirectUrl = httpResp.headers.location || '-'
        // 百度云盘不是https，坑爹，因为天翼云会多次302，所以这里要保持，跳转后的路径保持跟上次一致，经过本服务器代理就可以解密
        if (decryptTransform && passwdInfo.enable) {
          const key = crypto.randomUUID()
          await levelDB.setExpire(
            key,
            {
              redirectUrl,
              passwdInfo,
              fileSize,
              ...(request.redirectExtra || {}),
            },
            60 * 60 * 72
          )
          httpResp.headers.location = `/redirect/${key}?decode=1&lastUrl=${encodeURIComponent(url)}`
        }
        console.log('302 redirectUrl:', redirectUrl)
      } else if (httpResp.headers['content-range'] && httpResp.statusCode === 200) {
        response.statusCode = 206
      }

      // 设置headers
      for (const key in httpResp.headers) {
        response.setHeader(key, httpResp.headers[key])
      }
      if (request.beforeResponseHeaders) {
        request.beforeResponseHeaders(response, request)
      }

      // 下载时解密文件名
      if (method === 'GET' && response.statusCode === 200 && passwdInfo && passwdInfo.enable && passwdInfo.encName) {
        let fileName = decodeURIComponent(path.basename(url))
        fileName = decodeName(passwdInfo.password, passwdInfo.encType, fileName.replace(path.extname(fileName), ''))
        if (fileName) {
          let cd = response.getHeader('content-disposition')
          cd = cd ? cd.replace(/filename\*?=[^=;]*;?/g, '') : ''
          console.log('解密文件名...', reqId, fileName)
          response.setHeader('content-disposition', cd + `filename*=UTF-8''${encodeURIComponent(fileName)};`)
        }
      }

      httpResp
        .on('end', () => {
          resolve()
        })
        .on('close', () => {
          console.log('@远程响应关闭...', reqId, urlAddr)
          // response.destroy()
          if (decryptTransform) decryptTransform.destroy()
        })
      // 是否需要解密
      decryptTransform ? httpResp.pipe(decryptTransform).pipe(response) : httpResp.pipe(response)
    })
    httpReq.on('error', (err) => {
      console.log('@@httpProxy request error ', reqId, err, urlAddr, headers)
    })
    // 是否需要加密
    if (request.followRemoteRedirect && ['GET', 'HEAD'].includes(String(method).toLocaleUpperCase())) {
      httpReq.end()
    } else {
      encryptTransform ? request.pipe(encryptTransform).pipe(httpReq) : request.pipe(httpReq)
    }
    // 重定向的请求 关闭时 关闭被重定向的请求
    response.on('close', () => {
      console.log('@本地响应关闭...', reqId, url)
      httpReq.destroy()
    })
  })
}

export async function httpClient(request, response) {
  const { method, headers, urlAddr, reqBody, url } = request
  console.log('@@request_client: ', method, urlAddr, headers)
  // 创建请求
  const options = {
    method,
    headers,
    agent: ~urlAddr.indexOf('https') ? httpsAgent : httpAgent,
    rejectUnauthorized: false,
  }
  const httpRequest = ~urlAddr.indexOf('https') ? https : http
  return new Promise((resolve, reject) => {
    // 处理重定向的请求，让下载的流量经过代理服务器
    const httpReq = httpRequest.request(urlAddr, options, async (httpResp) => {
      console.log('@@statusCode', httpResp.statusCode, httpResp.headers)
      if (response) {
        response.statusCode = httpResp.statusCode
        for (const key in httpResp.headers) {
          response.setHeader(key, httpResp.headers[key])
        }
      }
      let result = ''
      httpResp
        .on('data', (chunk) => {
          result += chunk
        })
        .on('end', () => {
          resolve(result)
          console.log('httpResp响应结束...', url)
        })
    })
    httpReq.on('error', (err) => {
      console.log('@@httpClient request error ', err)
    })
    // check request type
    if (!reqBody) {
      url ? request.pipe(httpReq) : httpReq.end()
      return
    }
    // 发送请求
    typeof reqBody === 'string' ? httpReq.write(reqBody) : httpReq.write(JSON.stringify(reqBody))
    httpReq.end()
  })
}
