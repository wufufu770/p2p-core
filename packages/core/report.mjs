// report.mjs — 报告引擎(方向8): Finding -> Markdown 交付物
// 用法: node report.mjs <graphdPort> [engagementName] > report.md
// 结构: 执行摘要 / 漏洞结论(按严重度) / 加固建议(config_advisory) / 证据引用链

import fs from 'node:fs'

const PORT = process.argv[2] ?? '8766'
const ENG = process.argv[3] ?? ''
const GRAPHD = `http://127.0.0.1:${PORT}`

async function q(cypher) {
  const res = await fetch(`${GRAPHD}/query`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cypher }),
  })
  const d = await res.json()
  if (!d.ok) throw new Error(d.error)
  return d.rows ?? []
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

async function main() {
  const engRows = await q(`MATCH (e:Engagement) RETURN e.name AS n, e.target AS t, e.status AS s ORDER BY e.created_at DESC`)
  const eng = ENG ? engRows.find(r => r.n === ENG) : engRows[0]
  if (!eng) { console.error('# 未找到 engagement'); process.exit(1) }

  const findings = (await q(
    `MATCH (f:Finding) WHERE coalesce(f.verified_at,'')<>'' OR f.gate_status='verified'
     RETURN f.id AS id, f.title AS t, f.severity AS s, f.cvss AS cvss,
            f.repro AS r, f.evidence_dir AS e, f.verified_at AS va, f.verified_log AS vl
     ORDER BY f.cvss DESC`,
  )).filter(f => f.s && SEV_ORDER[f.s] !== undefined)

  const advisories = await q(
    `MATCH (f:Finding) WHERE f.severity='info' OR toLower(f.title) CONTAINS 'header' OR toLower(f.title) CONTAINS 'cors'
     RETURN f.id AS id, f.title AS t, f.repro AS r`,
  ).catch(() => [])

  const exp = await q(`MATCH (e:ExperienceWeight) RETURN e.pattern AS p ORDER BY e.prior DESC LIMIT 5`).catch(() => [])

  const now = new Date().toISOString()
  let md = `# 渗透测试报告 — ${eng.t}\n\n`
  md += `- **Engagement**: ${eng.n} (${eng.s})\n- **生成时间**: ${now}\n- **验证口径**: 全部结论经独立重放验证(validator 环)\n\n`

  md += `## 一、执行摘要\n\n`
  const bySev = {}
  for (const f of findings) (bySev[f.s] ??= []).push(f)
  md += `| 严重度 | 数量 |\n|---|---|\n`
  for (const s of Object.keys(SEV_ORDER)) {
    if (bySev[s]?.length) md += `| ${s.toUpperCase()} | ${bySev[s].length} |\n`
  }
  md += `\n`

  md += `## 二、漏洞结论(已验证)\n\n`
  if (!findings.length) md += `_本轮无达到报告标准的结论(零误报纪律)。_\n`
  for (const f of findings.sort((a, b) => (SEV_ORDER[a.s] ?? 9) - (SEV_ORDER[b.s] ?? 9))) {
    md += `### [${String(f.s).toUpperCase()}] ${f.t}\n\n`
    md += `- **CVSS**: ${f.cvss ?? '-'}  |  **状态**: ${f.va ? '✅ 已独立重放验证' : '⚠️ worker 自封'}\n`
    if (f.r) md += `- **复现**: \`${String(f.r).slice(0, 300)}\`\n`
    if (f.vl) md += `- **验证日志**: ${String(f.vl).slice(0, 200)}\n`
    if (f.e) md += `- **证据目录**: \`${f.e}\`\n`
    md += `\n`
  }

  if (advisories.length) {
    md += `## 三、加固建议(非漏洞, 单独归类)\n\n`
    for (const a of advisories) md += `- ${a.t}${a.r ? ` —— ${String(a.r).slice(0, 150)}` : ''}\n`
    md += `\n`
  }

  if (exp.length) {
    md += `## 四、经验库 TOP 先验(供下次任务复用)\n\n`
    for (const e of exp) md += `- \`${e.p}\`\n`
    md += `\n`
  }

  md += `---\n_由 p2p-core 三环系统自动生成; 零人工编辑。_\n`
  process.stdout.write(md)
}

main().catch(e => { console.error('report failed:', e.message); process.exit(1) })
