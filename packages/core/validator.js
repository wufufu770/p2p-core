// validator.js — 验证器环(方向2): Finding 的独立重放验证
// 原则: gate_status=verified 必须由机械重放背书, worker 自封不算数(XBOW/MAPTA 共识)
// N1 强化: 拆两级语义 —— reached(可达) 与 verified(断言命中)。仅 <400 且(可选)断言通过才 verified
// N5a 修复: 用 spawn('curl', argv) 替代 shell exec, 杜绝 repro 命令注入面

import { spawn } from 'node:child_process'

const ALLOWED_METHODS = /^(GET|HEAD|OPTIONS)\b/i
const MAX_EXEC_SECONDS = 20
const DANGEROUS_CHARS = /[`$]|\$\{|\b(;|&&|\|\|)\b/i
const STATUS_OK = (code) => code !== null && code >= 200 && code < 400

/** 从 repro 文本提取 curl 参数数组(不经 shell) */
export function extractCurlArgs(repro) {
  const text = String(repro ?? '').replace(/\\\n/g, ' ')
  const m = text.match(/curl\s+([^\n]*)/i)
  if (!m) {
    const u = text.match(/https?:\/\/[^\s"'`<>)]+/i)
    if (u) return ['-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', String(MAX_EXEC_SECONDS), u[0]]
    return null
  }
  // 解析 token: 保留引号包裹的 URL, 其余按空白切分
  const tokens = []
  const re = /"[^"]*"|'[^']*'|\S+/g
  let mm
  while ((mm = re.exec(m[1])) !== null) tokens.push(mm[0].replace(/^['"]|['"]$/g, ''))
  if (!tokens.length) return null
  // 方法安全闸
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === '-X' || tokens[i] === '--request') {
      const method = tokens[i + 1] || ''
      if (!ALLOWED_METHODS.test(method)) return null
    }
    // 危险 flag / shell 元字符拉黑
    if (/\s--resolve\b|\s(-x|--)proxy\b/.test(tokens[i])) return null
  }
  if (tokens.some(t => DANGEROUS_CHARS.test(t))) return null
  return tokens
}

/** spawn curl, 返回 {ok, httpCode, bodySample, ms, err} */
function runCurl(args, proxyUrl) {
  return new Promise((resolve) => {
    const full = proxyUrl ? [...args, '--proxy', proxyUrl] : args
    const t0 = Date.now()
    const child = spawn('curl', full, { timeout: MAX_EXEC_SECONDS * 1000 })
    let out = '', errOut = ''
    child.stdout.on('data', d => (out += d.toString()))
    child.stderr.on('data', d => (errOut += d.toString()))
    child.on('close', (code, signal) => {
      const killed = signal !== null || code === null
      resolve({
        ok: !killed,
        httpCode: parseInt(String(out).trim(), 10) || null,
        bodySample: String(out).slice(0, 300),
        err: killed ? 'timeout/killed' : (errOut || null),
        ms: Date.now() - t0,
      })
    })
    child.on('error', (e) => resolve({ ok: false, httpCode: null, bodySample: '', err: e.message, ms: Date.now() - t0 }))
  })
}

/**
 * 验证单条 Finding:
 * - reached: 可达(2xx/3xx)
 * - verified: reached 且(若 opts.assertions 提供)响应体命中任一断言
 * 状态机: gate_status ∈ {verified, reached, quarantined}
 */
export async function validateFinding(q, finding, opts = {}) {
  const proxy = process.env.P2P_PROXY_URL ?? ''
  const args = extractCurlArgs(finding.repro)
  let result
  if (!args) {
    result = { ok: false, reason: 'repro 无可安全重放的只读 curl' }
  } else {
    result = await runCurl(args, proxy || undefined)
    result.reason = result.ok
      ? `replayed ${result.httpCode ?? 'ok'} in ${result.ms}ms`
      : `upstream fail: ${result.err ?? result.httpCode}`
  }
  const reached = Boolean(result.ok && STATUS_OK(result.httpCode))
  // 断言(来自 profile must_repro_contains / 调用方)
  let verified = reached
  let assertHit = null
  const asserts = opts.assertions ?? []
  if (reached && asserts.length) {
    const body = String(result.bodySample ?? '').toLowerCase()
    assertHit = asserts.find(a => body.includes(String(a).toLowerCase())) ?? null
    verified = assertHit !== null
  }
  const gate = verified ? 'verified' : (reached ? 'reached' : 'quarantined')
  if (verified && result.bodySample && args) {
    await q(
      `MATCH (f:Finding {id:$id}) SET f.repro = f.repro + $body`,
      { id: finding.id, body: ` | replayed_response: ${String(result.bodySample).slice(0, 200)}` },
    ).catch((e) => opts.log?.('repro append failed:', e?.message))
  }
  const reason = asserts.length
    ? `${result.reason}; assertion=${assertHit ? 'HIT' : 'MISS'}(${(asserts||[]).join('|')})`
    : result.reason
  await q(
    `MATCH (f:Finding {id:$id}) SET f.gate_status=$g, f.verified_at=$at, f.verified_log=$lg`,
    { id: finding.id, g: gate,
      at: verified ? new Date().toISOString() : '',
      lg: `[validator] ${reason} | cmd=${String(args?.join(' ') ?? 'none').slice(0, 120)} | body=${String(result.bodySample ?? '').slice(0, 80)}` },
  ).catch((e) => opts.log?.('validator set failed:', e?.message))
  return { id: finding.id, verified, reached, gate, reason }
}

/** E1: 差分验证 —— baseline 为同端点正常响应特征; 注入类 finding 断言响应差异 */
export async function validateDifferential(q, baselineCache, log = () => {}) {
  const rows = await q(
    `MATCH (f:Finding) WHERE f.repro IS NOT NULL AND f.repro <> '' AND coalesce(f.verified_at,'')=''
     RETURN f.id AS id, f.title AS title, f.repro AS repro, f.category AS cat`,
  )
  const results = []
  for (const r of rows) {
    try {
      const cat = String(r.cat ?? '').toLowerCase()
      let assertions = []
      if (/sqli|sql/i.test(cat)) assertions = ['sql', 'syntax', 'mysql', 'postgres', 'error']
      else if (/ssrf/i.test(cat)) assertions = ['169.254', 'metadata', 'internal', 'localhost']
      else if (/rce|command/i.test(cat)) assertions = ['uid=', 'www-data', 'root']
      results.push(await validateFinding(q, r, { log, assertions }))
    } catch (e) { log('validateDifferential failed:', r.id, e?.message) }
  }
  return results
}

/** 扫描图中全部候选 Finding 并逐条验证(确定性, 不耗 LLM) */
export async function validateAll(q, log = () => {}, opts = {}) {
  const rows = await q(
    `MATCH (f:Finding) WHERE f.repro IS NOT NULL AND f.repro <> '' AND coalesce(f.verified_at,'')=''
     RETURN f.id AS id, f.title AS title, f.repro AS repro`,
  )
  const results = []
  for (const r of rows) {
    try {
      results.push(await validateFinding(q, r, { log, ...opts }))
    } catch (e) {
      log('validate failed:', r.id, e?.message)
    }
  }
  return results
}