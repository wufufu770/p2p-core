// p2p-core/scheduler.js — 三环并行渗透测试统一调度内核(宿主无关)
// HostAdapter 注入原语: spawnWorker/killAllWorkers/notify/log/registerCommand
// 行为保真清单见 adapters/README.md(#12/#16/#19/#22/#25 与硬规则 A-F)

import fs from 'node:fs'
import { validateAll } from './validator.js'
import { buildPlans, planFocus } from './planner.js'

export function BRIEFS(GRAPHD) {
  return {
    discovery: `你是三环系统的发现环 worker。广度要求(逐项执行): (1)/robots.txt 全部 Disallow 路径逐一访问; (2)首页HTML注释与链接解析; (3)常见敏感路径小字典探测(/flag.txt /backup.zip /.bak /admin /secret.key /console); (4)再走业务链路做缝隙轻验证。先读经验先验: curl -s -X POST ${GRAPHD}/query -H 'Content-Type: application/json' -d '{"cypher":"MATCH (e:ExperienceWeight) RETURN e.pattern AS p, e.prior AS w ORDER BY e.prior DESC LIMIT 10"}'。若某条经验确实帮到了你,回报计数(hits+1;有实质帮助再加 wins)。只允许写入这些已存在的表: Signal_/Endpoint/Finding/Hypothesis(禁止 CREATE/DROP TABLE,禁止自创表);推荐结构化端点 POST ${GRAPHD}/write/signal 与 POST ${GRAPHD}/write/finding。硬规则F(广度必含): 文件名/路径参数轻测 ../../etc/passwd(读到root:x即写Finding); 转账/兑换端点5连发并发重放后查余额差(异常即写Finding)。再对目标走完整业务链路做缝隙检测与轻量验证:枚举端点/参数,单点轻探测,结果写入图数据库。已排除方向也上报(status='refuted',weight=0.1)。预算最多15轮工具调用。`,
    deep: `你是深度攻击环 worker。先读经验先验(同发现环的 ExperienceWeight 查询)。再 curl ${GRAPHD}/query 查询 weight>=3 且 status='open' 的 Signal_,三层递进(L1基础→L2筛选+剪枝→L3跨端点组合)。总目标是拿最终产物而非证明漏洞:攻击链达成后立即提取敏感产物(flag/关键数据样本),写入 Finding.repro 与 checkpoint。写 Finding 推荐结构化端点 POST ${GRAPHD}/write/finding(JSON: id/title/severity/cvss/repro/category/gate_status='verified'),写信号用 /write/signal。剪枝信号置 status='pruned'。硬规则A(越权类): Finding.repro 必须含"低权限/未授权身份成功调用"的证据(状态码+响应体片段);仅有管理员身份可复现的一律只写 Signal 不写 Finding——管理员操作是正常功能。硬规则B(竞态类): 对转账/兑换/限额类端点必须并发重放≥5次同一请求(bash 里 & 后台连发 curl 后查余额差),余额/次数出现负值或超限即 verified。硬规则C(SSRF类): 遇到服务端发起URL的参数(头像/导入/webhook), 必试 http://169.254.169.254/latest/meta-data/ 与内网保留段, 回显 instance-id/ami-id 即 verified 证据。硬规则D(穿越类): 文件名/路径类参数必测 ../../etc/passwd 及 ..%2f..%2f%2e%2e 编码变体, 回显 root:x:0: 即 verified。硬规则E(落盘铁律): 每一个结论性成果必须当场写入图数据库——禁止只写本地 report.md/聊天文本, 图里没有=没做。预算最多14轮。`,
    creative: `你是创造探索环 worker。读取失败记录(status IN ['refuted','pruned'] 的 Signal_)与 open 的 Hypothesis,反转假设(有WAF↔无WAF/前端校验↔后端校验/技术栈误判),产出新 Hypothesis 节点(POST ${GRAPHD}/write/hypothesis)并用 SUGGESTS 边连接相关 Endpoint。fail 先验只代表降优先级: 快速验证不成立就放弃并记录, 不作为绝对禁入; 禁止原样重复已完整证伪的具体路径。预算最多8轮。`,
  }
}

export function createScheduler(adapter, config = {}) {
  const GRAPHD = config.graphdUrl ?? process.env.P2P_GRAPHD ?? 'http://127.0.0.1:8766'
  const RUNS_BASE = config.runsBase ?? process.env.P2P_RUNS_DIR ?? `${config.home ?? '/home/wff'}/runs`
  const ROLES_DIR = config.rolesDir ?? process.env.P2P_ROLES_DIR ?? `${config.coreDir ?? '.'}/roles`
  const CHAIN_MS = config.chainIntervalMs ?? 45_000
  const log = (...a) => adapter.log?.(...a)

  // #32: 宿主进程读取 graphd 的 .host-token, 经验库写操作需此凭证(worker 环境已剥离)
  let _hostToken
  try { _hostToken = fs.readFileSync(`${config.home ?? '/home/wff'}/d2d/graphd/.host-token`, 'utf8').trim() } catch {}
  async function q(cypher, params = {}) {
    const res = await fetch(`${GRAPHD}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(_hostToken ? { 'X-Auth': _hostToken } : {}) },
      body: JSON.stringify({ cypher, params }),
      signal: AbortSignal.timeout(10000),
    })
    const data = await res.json()
    if (!data.ok) throw new Error(`graphd: ${data.error}`)
    return data.rows ?? []
  }
  async function graphdUp() {
    try { return (await fetch(`${GRAPHD}/health`, { signal: AbortSignal.timeout(3000) })).ok } catch { return false }
  }

  // ---------- scope 门控 ----------
  const DESTRUCTIVE = [
    /rm\s+-rf?\s+\/(?!tmp)/,
    /\bmkfs(\.\w+)?\b/,
    /\bdd\b[^|]*\bof=\/dev\//,
    /\bshutdown\b|\breboot\b/,
    /DROP\s+(TABLE|DATABASE)/i,
  ]
  const URL_RE = /https?:\/\/[^\s"'`<>)]+/gi
  function hostOf(u) { try { return new URL(u).hostname.toLowerCase() } catch { return '' } }
  function checkBash(cmd, eng) {
    for (const re of DESTRUCTIVE) if (re.test(cmd)) return `危险命令被铁律拦截: ${re.source}`
    // P1(审查): 连接级旁路面拉黑 -- --resolve 改写解析 / -x·--proxy 外部代理 / -L 跟随跳出 scope 的重定向
    if (/\s--resolve\b/.test(cmd)) return 'OPSEC: --resolve 可绕过 scope 校验, 禁用'
    if (/\s(-x|--)proxy\b/.test(cmd)) return 'OPSEC: 外部代理可绕过出口治理, 禁用'
    if (/curl[^|]*\s-L\b/.test(cmd) && eng) return 'OPSEC: -L 重定向可能跳出 scope, 请手动逐跳验证'
    if (/\s--limit-rate\b/.test(cmd) === false && /curl\s+http/.test(cmd)) {
      // P2 最小速率治理: 注入限速提示由 brief 承担, 此处仅拦截明显轰击
    }
    if (/Engagement|AgentIdentity/.test(cmd) && /(SET|DELETE)/i.test(cmd))
      return '状态保护: worker 无权修改 Engagement/AgentIdentity 节点'
    if (!eng) return null
    const allowed = eng.scope.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    for (const u of cmd.match(URL_RE) ?? []) {
      const h = hostOf(u)
      if (!h || h === '127.0.0.1' || h === 'localhost') continue
      const ok = allowed.some((a) => h === a || h.endsWith(`.${a}`))
      if (!ok) return `越界目标被 scope 门控拦截: ${h} 不在授权范围 [${allowed.join(', ')}]`
    }
    return null
  }

  let _engCache = { eng: null, ts: 0 }
  async function resolveEngagement() {
    if (_engCache.ts > Date.now() - 60_000) return _engCache.eng
    try {
      const rows = await q(`MATCH (e:Engagement) WHERE e.status='active' RETURN e.scope AS s, e.name AS n LIMIT 1`)
      _engCache = { eng: rows[0]?.s ? { name: String(rows[0].n ?? ''), target: '', scope: String(rows[0].s), auth: 'declared' } : null, ts: Date.now() }
    } catch (e) { log('resolveEngagement:', e?.message); _engCache = { eng: null, ts: Date.now() } }
    return _engCache.eng
  }

  const state = { eng: null, objective: '', workers: new Map(), deepWakeups: 0, creativeWakeups: 0, idleStreak: 0, lastSigTotal: -1, chainTimer: undefined }

  // ---------- 角色素材库 ----------
  let _rolesCache = null
  function loadRoles() {
    if (_rolesCache) return _rolesCache
    try {
      _rolesCache = fs.readdirSync(ROLES_DIR).filter((f) => f.endsWith('.json'))
        .map((f) => JSON.parse(fs.readFileSync(`${ROLES_DIR}/${f}`, 'utf8')))
    } catch (e) { log('loadRoles:', e?.message); _rolesCache = [] }
    return _rolesCache
  }
  function pickRole(ring, chain, wakeups = 0) {
    const roles = loadRoles().filter((r) => r.rings?.includes(ring))
    if (!roles.length) return null
    if (ring === 'discovery')
      return roles.find((r) => (r.match_chains ?? []).includes(chain)) || roles.find((r) => (r.match_chains ?? []).includes('*')) || roles[0]
    if (ring === 'creative') {
      const theorist = roles.find((r) => r.id === 'redteam-theorist')
      const freshEyes = roles.find((r) => r.id === 'dev-fresh-eyes')
      return wakeups % 2 === 1 ? theorist || roles[0] : freshEyes || roles[0]
    }
    return null
  }
  function pickDeepRole(topSignalTypes = []) {
    const deepRoles = loadRoles().filter((r) => r.rings?.includes('deep'))
    let best = null, bestScore = -1
    for (const r of deepRoles) {
      const aff = r.signal_affinity ?? []
      if (!aff.length) continue
      const score = topSignalTypes.filter((t) => aff.some((a) => t.toLowerCase().includes(a))).length
      if (score > bestScore) { bestScore = score; best = r }
    }
    return bestScore > 0 ? best : deepRoles.find((r) => r.id === 'exploit-chainer') || deepRoles[0] || null
  }

  function runLog(engName, entry) {
    try {
      const dir = `${RUNS_BASE}/${engName}`
      fs.mkdirSync(dir, { recursive: true })
      fs.appendFileSync(`${dir}/run-log.jsonl`, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n')
    } catch (e) { log('runLog:', e?.message) }
  }
  function collectContextRefs(engName, excludeWid) {
    try {
      const base = `${RUNS_BASE}/${engName}/artifacts`
      return fs.readdirSync(base)
        .filter((d) => d !== excludeWid && fs.existsSync(`${base}/${d}/handoff.md`))
        .map((d) => `${base}/${d}/handoff.md`)
    } catch { return [] }
  }

  // ---------- worker 派发 ----------
  async function runWorker(ring, chain, focus) {
    const eng = state.eng
    if (!eng) return '无活跃 engagement'
    const wid = `${eng.name}-${ring}-${Math.random().toString(36).slice(2, 6)}`
    await q(
      `CREATE (a:AgentIdentity {worker_id:$w, ring:$r, chain:$c, status:'running', checkpoint:'', todo:'', updated_at:$t})`,
      { w: wid, r: ring, c: chain, t: new Date().toISOString() },
    )
    let role = null
    if (ring === 'deep') {
      let topTypes = []
      try {
        topTypes = (await q(`MATCH (s:Signal_) WHERE s.status='open' RETURN s.type AS t LIMIT 12`)).map((r) => String(r.t ?? ''))
      } catch (e) { log('signal types:', e?.message) }
      role = pickDeepRole(topTypes)
    } else {
      role = pickRole(ring, chain, state.creativeWakeups)
    }
    const roleBlock = role ? `\n## 你的角色\n${role.display_name}(id=${role.id}): ${role.persona}` : ''
    const artifactDir = `${RUNS_BASE}/${eng.name}/artifacts/${wid}`
    try { fs.mkdirSync(artifactDir, { recursive: true }) } catch (e) { log('mkdir:', e?.message) }
    const refs = ring !== 'discovery' ? collectContextRefs(eng.name, wid) : []
    const refsBlock = refs.length ? `\n## 上游成员产物(动手前先读这些交接文件)\n${refs.map((r) => '- ' + r).join('\n')}` : ''
    const artifactsBlock = `\n## 产物落盘(硬性, handoff 制度)\n你的专属产物目录: ${artifactDir}\n收工前必须写入两个文件: evidence.md(关键原始请求/响应证据) 与 handoff.md(完成事项/发现清单/未决方向, 给下一个成员看)。图里写 Finding 是给评估器, 这两个文件是给接力者。`
    const proxyEnv = process.env.P2P_PROXY_URL
      ? `\n## OPSEC 出口纪律\n所有 curl 必须走代理: 在每条命令前加 env http_proxy=${process.env.P2P_PROXY_URL} https_proxy=${process.env.P2P_PROXY_URL}; 同一端点连续请求间隔≥2秒`
      : '\n## OPSEC 出口纪律\n同一端点连续请求间隔≥2秒; 单端点请求总数≤50'
    const boundary = `${proxyEnv}\n\n## 边界(铁律,违反即失败)\n- 仅测授权 scope 内目标\n- 禁止 rm -rf /、mkfs、dd、shutdown;禁止 DROP TABLE 类破坏性 payload\n- 内存受限主机: 禁止 docker run / apt install / npm install 类重操作\n- 预算最后 20% 轮次必须用于结果落盘上报\n- 禁止修改 Engagement/AgentIdentity 节点(归仲裁层所有); 只写 Signal_/Endpoint/Finding/Hypothesis
- 负向探测结果(端点不存在/不适用/无此功能)只写 status='refuted' 的 Signal, 禁止写成 Finding`
    const obj = `\n## 总目标(最终交付物)\n${state.objective}`
    const briefs = BRIEFS(GRAPHD)
    const gapHints = process.env.P2P_GAP_HINTS || ''
    const gapLine = gapHints ? `\n## 上一轮自评缺口(本轮必须优先覆盖, 来自自身覆盖报告而非外部答案): ${gapHints}` : ''
    const task = `${briefs[ring]}${obj}${boundary}${roleBlock}${artifactsBlock}${refsBlock}${gapLine}${focus ? `\n重点: ${focus}` : ''}\n\nTask 执行开始。`
    runLog(eng.name, { event: 'dispatch', worker_id: wid, ring, chain, role: role?.id ?? 'default' })
    const p = adapter.spawnWorker({ ring, task })
      .then(async ({ code, text }) => {
        await q(
          `MATCH (a:AgentIdentity {worker_id:$w}) SET a.status=$s, a.checkpoint=$cp, a.updated_at=$t`,
          { w: wid, s: code === 0 ? 'done' : 'error', cp: (text ?? '').slice(-800), t: new Date().toISOString() },
        ).catch((e) => log('checkpoint:', e?.message))
        runLog(eng.name, { event: 'terminal', worker_id: wid, ring, code })
        state.workers.delete(wid)
        log(`worker ${wid}[${ring}] exit=${code}`)
      })
      .catch((e) => log('worker crashed:', e?.message))
    state.workers.set(wid, p)
    return wid
  }

  // ---------- 经验沉淀 v2(方言归一 + 拉普拉斯先验) ----------
  const CANON_MAP = [
    [/^(ew[-_]?ref|ewref)[-_:]?/, 'fail:'],
    [/^(ew[-_]?)/, ''],
    [/^(exp)[-_]?/, ''],
    [/^(succ|win|ok|hit)[-_:]?/, 'succ:'],
    [/^(fail|ref|refuted|pruned|bad|miss)[-_:]?/, 'fail:'],
  ]
  function normPattern(raw) {
    let p = String(raw ?? '').toLowerCase().replace(/[^a-z0-9:_\/-]/g, '')
    for (const [re, to] of CANON_MAP) p = p.replace(re, to)
    if (!/^(succ|fail):/.test(p)) p = 'succ:' + p
    return p.slice(0, 64)
  }
  const laplace = (wins, hits) => Math.round(((wins + 1) / (hits + 2)) * 100) / 100
  async function upsertExperience(patternRaw, win) {
    const pat = normPattern(patternRaw)
    let wins = 0, hits = 0
    try {
      const rows = await q(`MATCH (e:ExperienceWeight {id:$id}) RETURN e.wins AS w, e.hits AS h`, { id: pat })
      if (rows[0]) { wins = Number(rows[0].w ?? 0); hits = Number(rows[0].h ?? 0) }
    } catch (e) { log('exp read:', e?.message) }
    wins += win ? 1 : 0; hits += 1
    const prior = laplace(wins, hits)
    await q(
      `MERGE (e:ExperienceWeight {id:$id}) SET e.pattern=$pat, e.stack='web', e.wins=$w, e.hits=$h, e.prior=$p, e.target_type='web'`,
      { id: pat, pat, w: wins, h: hits, p: prior },
    ).catch(() => {})
    return `${pat}=${prior}`
  }
  async function dedupFindings() {
    const rows = await q(`MATCH (f:Finding) RETURN f.id AS id, f.title AS t, f.severity AS sev`)
    const rank = { critical: 3, high: 2, medium: 1, low: 0, info: -1 }
    const groups = {}
    for (const r of rows) {
      const sig = String(r.t ?? '').toLowerCase().replace(/[^a-z0-9 ]/g, '').split(/\s+/)
        .filter((w) => w.length > 3).sort().join('|')
      ;(groups[sig] ??= []).push(r)
    }
    let removed = 0
    for (const [, g] of Object.entries(groups)) {
      if (g.length < 2) continue
      g.sort((a, b) => (rank[b.sev] ?? 0) - (rank[a.sev] ?? 0))
      for (const dup of g.slice(1)) {
        await q(`MATCH (f:Finding {id:$id}) DETACH DELETE f`, { id: dup.id }).catch(() => {})
        removed++
      }
    }
    return removed
  }
  async function harvest() {
    const written = []
    const succ = await q(`MATCH (f:Finding)-[:CONFIRMS]->(s:Signal_) RETURN DISTINCT s.type AS t LIMIT 20`)
    for (const r of succ) written.push(await upsertExperience(String(r.t ?? ''), true))
    const fails = await q(`MATCH (s:Signal_) WHERE s.status IN ['refuted','pruned'] RETURN DISTINCT s.type AS t LIMIT 20`)
    const confirmed = await q(`MATCH (f:Finding)-[:CONFIRMS]->(s:Signal_) RETURN DISTINCT s.type AS t LIMIT 20`)
    const okTypes = new Set(confirmed.map((r) => String(r.t)))
    for (const r of fails) {
      const t = String(r.t ?? '')
      if (okTypes.has(t)) continue
      written.push(await upsertExperience(t, false))
    }
    const removed = await dedupFindings()
    if (removed) written.push(`dedup:-${removed}`)
    return written
  }

  // ---------- 链式调度(确定性仲裁) ----------
  function startChainLoop() {
    stopChainLoop()
    state.chainTimer = setInterval(() => {
      if (!state.eng) return stopChainLoop()
      void (async () => {
        try {
          const _trace = { w: state.workers.size }
          if (state.workers.size > 0) { runLog(state.eng?.name ?? '?', { event: 'tick', ..._trace, skip: 'workers' }); return }
          // #22 心跳窗口
          const cutoff = new Date(Date.now() - 30 * 60_000).toISOString()
          const runningN = Number((await q(
            `MATCH (a:AgentIdentity) WHERE a.status='running' AND a.updated_at >= $c RETURN count(a) AS c`,
            { c: cutoff },
          ))[0]?.c ?? 0)
          _trace.runningN = runningN
          if (runningN > 0) { runLog(state.eng.name, { event: 'tick', ..._trace, skip: 'runningN' }); return }
          const high = Number((await q(`MATCH (s:Signal_) WHERE s.weight>=3 AND s.status='open' RETURN count(s) AS c`))[0]?.c ?? 0)
          const findings = Number((await q(`MATCH (f:Finding) RETURN count(f) AS c`))[0]?.c ?? 0)
          // #12 verified 判据
          const verified = Number((await q(`MATCH (f:Finding) WHERE f.gate_status='verified' RETURN count(f) AS c`))[0]?.c ?? 0)
          const hyps = Number((await q(`MATCH (h:Hypothesis) WHERE h.status='open' RETURN count(h) AS c`))[0]?.c ?? 0)
          Object.assign(_trace, { high, findings, verified, hyps, dw: state.deepWakeups, cw: state.creativeWakeups })
          if (high > 0 && verified === 0 && state.deepWakeups < 3) {
            runLog(state.eng.name, { event: 'tick', ..._trace, branch: 'deep' })
            // 方向4: 规划器排序攻击假设, 注入 deep brief focus
            let focus
            try {
              const plans = await buildPlans(q)
              focus = planFocus(plans)
              if (plans.length) adapter.notify(`规划器: ${plans.length} 条计划已生成(最高分 ${plans[0].score})`)
            } catch (e) { log('planner:', e?.message) }
            adapter.notify(`自动调度: 深度环启动 (${high} 高权重信号)`)
            runLog(state.eng.name, { event: 'wake-deep', n: state.deepWakeups + 1, high_signals: high })
            try {
              await runWorker('deep', 'signal-consumer', focus)
              state.deepWakeups++   // F5: 仅派发成功才计数
            } catch (e) { log('deep spawn failed:', e?.message) }
            return
          }
          // #19 verified 后闭环沉淀
          if (verified > 0 && hyps === 0) {
            // 方向2 验证器环: worker 自封的 verified 必须经独立重放背书
            if (!state.validatedAt) {
              adapter.notify('验证器环: 独立重放全部候选 Finding...')
              const rs = await validateAll(q, (...a) => log(...a)).catch((e) => { log('validateAll:', e?.message); return [] })
              state.validatedAt = Date.now()
              const okN = rs.filter(r => r.verified).length
              adapter.notify(`验证完成: ${okN}/${rs.length} 通过重放, 其余隔离`)
              runLog(state.eng.name, { event: 'validated', total: rs.length, passed: okN })
              return   // 下一 tick 以机械验证后的状态重新判定
            }
            adapter.notify('目标达成(verified>=1 且无未消化假设): 执行经验沉淀并冻结')
            await harvest()
            await q(`MATCH (e:Engagement {name:$n}) SET e.status='completed'`, { n: state.eng.name })
            runLog(state.eng.name, { event: 'close', outcome: 'completed' })
            state.eng = null
            stopChainLoop()
            return
          }
          // #16 假设孤儿消费(优先于稳定判定)
          if (hyps > 0 && state.creativeWakeups < 5) {
            state.creativeWakeups++
            const hys = await q(`MATCH (h:Hypothesis) WHERE h.status='open' RETURN h.text AS t LIMIT 6`).catch(() => [])
            adapter.notify(`假设待消费(${hys.length}条open) → 创造环第${state.creativeWakeups}次唤醒验证/反驳`)
            runLog(state.eng.name, { event: 'wake-creative-hyps', n: state.creativeWakeups })
            await runWorker('creative', 'reflection', '优先逐条验证或反驳图中 open 的 Hypothesis')
            return
          }
          // #28 修复: 唤醒预算耗尽后不再让 open 假设阻塞收敛 —— 按现状闭环
          if (findings > 0 && high === 0 && (hyps === 0 || state.creativeWakeups >= 5)) {
            const sigTotal = Number((await q(`MATCH (s:Signal_) RETURN count(s) AS c`))[0]?.c ?? 0)
            const stable = sigTotal === state.lastSigTotal
            state.lastSigTotal = sigTotal
            if (!stable) { state.idleStreak++; return }
            state.idleStreak++
            if (state.idleStreak < 2) return
            // 方向2 验证器环: worker 自封的 verified 必须经独立重放背书
            if (!state.validatedAt) {
              adapter.notify('验证器环: 独立重放全部候选 Finding...')
              const rs = await validateAll(q, (...a) => log(...a)).catch((e) => { log('validateAll:', e?.message); return [] })
              state.validatedAt = Date.now()
              const okN = rs.filter(r => r.verified).length
              adapter.notify(`验证完成: ${okN}/${rs.length} 通过重放, 其余隔离`)
              runLog(state.eng.name, { event: 'validated', total: rs.length, passed: okN })
              return   // 下一 tick 以机械验证后的状态重新判定
            }
            adapter.notify('目标闭环(连续两轮稳定): 执行经验沉淀')
            await harvest()
            await q(`MATCH (e:Engagement {name:$n}) SET e.status='completed'`, { n: state.eng.name })
            runLog(state.eng.name, { event: 'close', outcome: 'completed' })
            state.eng = null
            stopChainLoop()
            return
          }
          state.idleStreak = 0
          if (findings === 0 && state.creativeWakeups >= 3) {
            adapter.notify('唤醒耗尽仍无发现: 关闭为 exhausted 并标记 NEED_INPUT')
            runLog(state.eng.name, { event: 'close', outcome: 'exhausted' })
            await q(`MATCH (e:Engagement {name:$n}) SET e.status='exhausted'`, { n: state.eng.name })
            state.eng = null
            stopChainLoop()
            return
          }
          if (findings === 0 && high === 0 && hyps === 0 && state.creativeWakeups < 3) {
            state.creativeWakeups++
            const fails = await q(`MATCH (s:Signal_) WHERE s.status IN ['refuted','pruned'] RETURN s.id AS id, s.evidence AS ev LIMIT 8`)
            const summary = fails.map((r) => `${r.id}:${String(r.ev ?? '').slice(0, 40)}`).join('; ')
            adapter.notify(`三环空闲无进展 → 自动反思唤醒(${state.creativeWakeups}/3)。失败: ${summary}`)
            runLog(state.eng.name, { event: 'wake-creative-idle', n: state.creativeWakeups })
            await runWorker('creative', 'reflection', summary)
          }
        } catch (e) { log('chain tick:', e?.message) }
      })()
    }, CHAIN_MS)
  }
  function stopChainLoop() {
    if (state.chainTimer) clearInterval(state.chainTimer)
    state.chainTimer = undefined
  }

  async function statusText() {
    if (!state.eng) return '无活跃 engagement。用 pentest 启动命令开始。'
    const cnt = async (label, cy) => {
      try {
        const r = await q(cy)
        return `${label}=${JSON.stringify(Object.values(r[0] ?? {})[0] ?? 0)}`
      } catch { return `${label}=?` }
    }
    return [
      `engagement: ${state.eng.name}`,
      `objective: ${state.objective}`,
      await cnt('endpoints', 'MATCH (x:Endpoint) RETURN count(x)'),
      await cnt("signals_open", "MATCH (x:Signal_) WHERE x.status='open' RETURN count(x)"),
      await cnt('findings', 'MATCH (x:Finding) RETURN count(x)'),
      await cnt('experience', 'MATCH (x:ExperienceWeight) RETURN count(x)'),
      `workers_local=${state.workers.size} deep_wakeups=${state.deepWakeups} creative_wakeups=${state.creativeWakeups}`,
    ].join('\n')
  }

  async function startEngagement(target, scope, instances = 2) {
    if (!(await graphdUp())) throw new Error(`graphd 未运行 (${GRAPHD})`)
    let host = target
    try { host = new URL(target.startsWith('http') ? target : `https://${target}`).hostname } catch {}
    const sc = scope || String(host).replace(/^www\./, '')
    const name = `eng-${Date.now().toString(36)}`
    await q(
      `CREATE (e:Engagement {name:$n, target:$t, scope:$s, auth:'declared', status:'active', created_at:$ts})`,
      { n: name, t: target, s: sc, ts: new Date().toISOString() },
    )
    state.eng = { name, target, scope: sc, auth: 'declared' }
    state.objective = '拿到目标敏感产物(flag/关键数据样本), 不止于证明漏洞'
    state.deepWakeups = 0
    state.creativeWakeups = 0
    state.lastSigTotal = -1
    state.idleStreak = 0
    const n = Math.min(Math.max(parseInt(instances ?? '2', 10) || 2, 1), 4)
    for (const chain of ['auth', 'core-features', 'api-surface', 'content'].slice(0, n)) {
      await runWorker('discovery', chain)
    }
    startChainLoop()
    runLog(name, { event: 'engagement-start', target, scope: sc, instances: n })
    // #14 宿主活到终态
    const DEADLINE = Date.now() + 90 * 60_000
    await new Promise((res) => {
      const watch = setInterval(async () => {
        try {
          if (Date.now() > DEADLINE) { clearInterval(watch); return res() }
          const row = (await q(`MATCH (e:Engagement {name:$n}) RETURN e.status AS s`, { n: name }))[0]
          if (!row || row.s !== 'active') { clearInterval(watch); return res() }
        } catch (e) { log('watch:', e?.message) }
      }, 30_000)
    })
    const final = (await q(`MATCH (e:Engagement {name:$n}) RETURN e.status AS s`, { n: name }))[0]?.s ?? 'unknown'
    return `engagement ${name} 终态(${final}), 调度闭环结束`
  }

  async function stopAll() {
    stopChainLoop()
    const killed = adapter.killAllWorkers?.() ?? 0
    for (const [wid] of state.workers)
      await q(`MATCH (a:AgentIdentity {worker_id:$w}) SET a.status='stopped'`, { w: wid }).catch(() => {})
    state.workers.clear()
    if (state.eng)
      await q(`MATCH (e:Engagement {name:$n}) SET e.status='frozen'`, { n: state.eng.name }).catch(() => {})
    state.eng = null
    return killed
  }

  return { q, graphdUp, checkBash, resolveEngagement, state, runWorker, harvest, statusText, startEngagement, stopAll, startChainLoop, stopChainLoop, runLog, GRAPHD }
}
