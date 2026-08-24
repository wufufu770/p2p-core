#!/usr/bin/env node
// proxygate — OPSEC 出口治理层(方向3 最小版)
// 职责: ①连接层 scope 白名单(--resolve/DNS rebinding 全部失效) ②per-host 令牌桶限速 ③全量请求审计落盘
// 用法: P2P_PROXY_PORT=8888 P2P_PROXY_ALLOW="127.0.0.1,localhost" node proxygate.js
// worker 侧只需 export http_proxy=http://127.0.0.1:8888 https_proxy=...
import http from 'node:http'
import net from 'node:net'
import { mkdirSync, appendFileSync } from 'node:fs'

const PORT = parseInt(process.env.P2P_PROXY_PORT ?? '8888', 10)
const ALLOW = new Set((process.env.P2P_PROXY_ALLOW ?? '127.0.0.1,localhost')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean))
const RATE = parseFloat(process.env.P2P_PROXY_RATE ?? '5') // req/s per host
const EVIDENCE_DIR = process.env.P2P_PROXY_EVIDENCE ?? '/home/wff/d2d/evidence/proxy'
const LOG_ENABLED = process.env.P2P_PROXY_LOG !== '0'

try { mkdirSync(EVIDENCE_DIR, { recursive: true }) } catch {}
const logFile = `${EVIDENCE_DIR}/proxy-${Date.now()}.jsonl`
function audit(entry) {
  if (!LOG_ENABLED) return
  try { appendFileSync(logFile, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n') } catch {}
}

// ---- per-host 令牌桶 ----
const buckets = new Map()
function allowRate(host) {
  const now = Date.now()
  let b = buckets.get(host)
  if (!b) { b = { tokens: RATE, last: now }; buckets.set(host, b) }
  b.tokens = Math.min(RATE, b.tokens + ((now - b.last) / 1000) * RATE)
  b.last = now
  if (b.tokens < 1) return false
  b.tokens -= 1
  return true
}

function hostAllowed(host) {
  const h = String(host || '').toLowerCase().replace(/:\d+$/, '')
  return ALLOW.has(h)
}

// ---- HTTP absolute-form 转发(curl 设了 http_proxy 就长这样) ----
const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host ?? 'unknown'}`)
  const host = u.hostname.toLowerCase()
  audit({ kind: 'http', method: req.method, host, url: req.url })
  if (!hostAllowed(host)) {
    res.writeHead(403, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ error: `proxygate: host "${host}" not in scope` }))
  }
  if (!allowRate(host)) {
    res.writeHead(429, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ error: 'proxygate: rate limited' }))
  }
  const upstream = http.request({
    host: u.hostname, port: u.port || 80, path: u.pathname + u.search,
    method: req.method, headers: { ...req.headers, host: u.host },
  }, (ur) => {
    // 重定向逐跳复检 Location 的 host
    const loc = ur.headers.location
    if (loc) {
      try {
        const lu = new URL(loc, u)
        if (!hostAllowed(lu.hostname)) {
          res.writeHead(502, { 'Content-Type': 'application/json' })
          return res.end(JSON.stringify({ error: `proxygate: redirect to "${lu.hostname}" leaves scope` }))
        }
      } catch {}
    }
    res.writeHead(ur.statusCode, ur.headers)
    ur.pipe(res)
  })
  upstream.on('error', (e) => {
    res.writeHead(502, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: `proxygate upstream: ${e.message}` }))
  })
  req.pipe(upstream)
})

// ---- CONNECT 隧道(https): 在握手层校验 SNI 主机名, 不解析内容 ----
server.on('connect', (req, socket, head) => {
  const host = (req.url || '').split(':')[0].toLowerCase()
  audit({ kind: 'connect', host, url: req.url })
  if (!hostAllowed(host)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
    return socket.destroy()
  }
  if (!allowRate(host)) {
    socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n')
    return socket.destroy()
  }
  const upstream = net.connect(parseInt(req.url.split(':')[1] ?? '443', 10), host, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (head?.length) upstream.write(head)
    upstream.pipe(socket)
    socket.pipe(upstream)
  })
  upstream.on('error', () => socket.destroy())
  socket.on('error', () => upstream.destroy())
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[proxygate] :${PORT} allow=[${[...ALLOW].join(',')}] rate=${RATE}/s log=${logFile}`)
})
