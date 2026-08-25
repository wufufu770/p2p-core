// planner.js — 攻击假设规划器(方向4, 规则版)
// 从图拓扑评分生成 top-N 攻击计划: score = signal_weight × (1+prior) × class_severity
// 产出 Plan 节点(chosen/abandoned 留痕防重复探索), 并作为 deep 环 brief 的 focus 注入

export async function buildPlans(q, opts = {}) {
  const topN = opts.topN ?? 3
  // 经验先验
  const expRows = await q(`MATCH (e:ExperienceWeight) RETURN e.pattern AS p, e.prior AS prior`).catch(() => [])
  const priorOf = {}
  for (const r of expRows) {
    const key = String(r.p ?? '').replace(/^(succ|fail):/, '').toLowerCase()
    if (!key) continue
    priorOf[key] = Math.max(priorOf[key] ?? 0, Number(r.prior ?? 0))
  }
  const SEV = { critical: 1.5, high: 1.2, medium: 1.0, low: 0.6, info: 0.3 }

  // 候选 = open 且 weight>=2 的信号, 关联端点数越多越值得深入
  const cands = await q(
    `MATCH (s:Signal_) WHERE s.weight >= 2 AND s.status='open'
     OPTIONAL MATCH (s)-[:AT]->(e:Endpoint)
     RETURN s.id AS id, s.type AS type, s.weight AS w, s.evidence AS ev,
            count(e) AS eps LIMIT 40`,
  ).catch(() => [])

  // 已有 verified Finding 的类型降权(避免重复主攻已达成方向)
  const doneTypes = new Set(
    (await q(
      `MATCH (f:Finding)-[:CONFIRMS]->(s:Signal_) WHERE f.gate_status='verified' RETURN DISTINCT s.type AS t`,
    ).catch(() => [])).map((r) => String(r.t ?? '')),
  )

  const scored = cands.map((c) => {
    const t = String(c.type ?? '').toLowerCase()
    let score = Number(c.w ?? 1) * (Number(c.eps ?? 0) + 1)
    for (const [k, v] of Object.entries(priorOf)) {
      if (t.includes(k)) { score *= 1 + v; break }
    }
    if (doneTypes.has(t)) score *= 0.4   // 已有成果的类型降权, 让位新方向
    return { type: t, id: String(c.id ?? ''), ev: String(c.ev ?? '').slice(0, 60), score: Math.round(score * 100) / 100 }
  }).sort((a, b) => b.score - a.score).slice(0, topN)

  // 落 Plan 节点
  const plans = []
  for (const s of scored) {
    const id = `plan-${s.id}-${Math.random().toString(36).slice(2, 6)}`
    await q(
      `CREATE (p:Plan {id:$id, text:$txt, score:$sc, status:'chosen', created_at:$ts})`,
      { id, txt: `主攻信号类型 ${s.type} (score=${s.score}, 证据:${s.ev})`, sc: s.score, ts: new Date().toISOString() },
    ).catch(() => {})
    plans.push({ id, text: `优先验证信号类型「${s.type}」相关端点与参数(历史成功率加权最高)`, score: s.score })
  }
  return plans
}

/** 生成 deep worker 的 focus 文本 */
export function planFocus(plans) {
  if (!plans?.length) return undefined
  return '按规划器排序执行: ' + plans.map((p, i) => `${i + 1}. ${p.text}`).join('; ')
}
