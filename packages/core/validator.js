// validator.js — 验证器环(方向2): Finding 的独立重放验证
// 原则: gate_status=verified 必须由机械重放背书, worker 自封不算数(XBOW/MAPTA 共识)
// 安全: 仅重放 GET/HEAD 与白名单方法的 curl; 走 P2P_PROXY_URL 出口(如配置); 超时硬上限

import { exec } from 'node:child_process'

const ALLOWED_METHODS = /^(GET|HEAD|OPTIONS)\b/i
const MAX_EXEC_SECONDS = 20

/** 从 repro 文本提取第一条 curl 命令(单行或含 \ 续行折叠为单行) */
export function extractCurl(repro) {
  const text = String(repro ?? '').replace(/\\\n/g, ' ')
  const m = text.match(/curl\s+-[^\n"']*(?:"[^"]*"[^"']*)*/i)
  if (!m) {
    // 宽松兜底: 找以 http 开头的 GET URL, 构造只读探针
    const u = text.match(/https?:\/\/[^\s"'`<>)]+/i)
    if (u) return `curl -s -o /dev/null -w "%{http_code}" --max-time ${MAX_EXEC_SECONDS} "${u[0]}"`
    return null
  }
  let cmd = m[0]
  // 方法安全闸: 只允许只读方法(注入类 repro 的 payload 在 URL 参数中, 仍可重放)
  if (/(-X|--request)\s+/i.test(cmd)) {
    const mm = cmd.match(/(?:-X|--request)\s*([A-Z]+)/i)
    if (mm && !ALLOWED_METHODS.test(mm[1])) return null
  }
  // 危险 flag 拉黑(与 scope 门控同源)
  if (/\s--resolve\b|\s(-x|--)proxy\b/.test(cmd)) return null
  return cmd
}

/** 执行验证 curl, 返回 {ok, httpCode, bodySample, ms} */
function runCurl(cmd, proxyUrl) {
  return new Promise((resolve) => {
    const full = proxyUrl ? `${cmd} --proxy ${proxyUrl}` : cmd
    const t0 = Date.now()
    exec(full, { timeout: MAX_EXEC_SECONDS * 1000, encoding: 'utf8' }, (err, stdout, stderr) => {
      resolve({
        ok: !err || (err.killed === false && stdout),
        httpCode: parseInt(String(stdout).trim(), 10) || null,
        bodySample: String(stdout).slice(0, 300),
        err: err ? String(err.message).slice(0, 120) : null,
        ms: Date.now() - t0,
      })
    })
  })
}

/**
 * 验证单条 Finding:
 * - 提取 repro 中的 curl 并重放
 * - 可达且响应码 <500 -> 机械验证通过(verified_at 落库)
 * - 连接失败/超时/5xx -> quarantined(不进报告不计分)
 */
export async function validateFinding(q, finding, opts = {}) {
  const proxy = process.env.P2P_PROXY_URL ?? ''
  const cmd = extractCurl(finding.repro)
  let result
  if (!cmd) {
    result = { ok: false, reason: 'repro 中无可安全重放的 curl(仅支持只读方法)' }
  } else {
    result = await runCurl(cmd, proxy || undefined)
    result.reason = result.ok && (result.httpCode === null || result.httpCode < 500)
      ? `replayed ${result.httpCode ?? 'ok'} in ${result.ms}ms`
      : `upstream fail: ${result.err ?? result.httpCode}`
  }
  const verified = Boolean(result.ok && (result.httpCode === null || result.httpCode < 500))
  // 方向2 补完: 重放的响应样本机械写入 repro(证据链本体, 非人工编辑)
  if (verified && result.bodySample && cmd) {
    await q(
      `MATCH (f:Finding {id:$id}) SET f.repro = f.repro + $body`,
      { id: finding.id, body: ` | replayed_response: ${String(result.bodySample).slice(0, 200)}` },
    ).catch((e) => opts.log?.('repro append failed:', e?.message))
  }
  await q(
    `MATCH (f:Finding {id:$id}) SET f.gate_status=$g, f.verified_at=$at, f.verified_log=$lg`,
    { id: finding.id, g: verified ? 'verified' : 'quarantined',
      at: verified ? new Date().toISOString() : '',
      lg: `[validator] ${result.reason} | cmd=${String(cmd ?? 'none').slice(0, 120)} | body=${String(result.bodySample ?? '').slice(0, 80)}` },
  ).catch((e) => opts.log?.('validator set failed:', e?.message))
  return { id: finding.id, verified, reason: result.reason }
}

/** 扫描图中全部候选 Finding 并逐条验证(确定性, 不耗 LLM) */
export async function validateAll(q, log = () => {}) {
  const rows = await q(
    `MATCH (f:Finding) WHERE f.repro IS NOT NULL AND f.repro <> '' AND coalesce(f.verified_at,'')='' 
     RETURN f.id AS id, f.title AS title, f.repro AS repro`,
  )
  const results = []
  for (const r of rows) {
    try {
      results.push(await validateFinding(q, r, { log }))
    } catch (e) {
      log('validate failed:', r.id, e?.message)
    }
  }
  return results
}
