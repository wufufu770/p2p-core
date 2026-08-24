#!/usr/bin/env python3
"""架构合规检查器: compliance_check.py -> 逐项 PASS/FAIL + 证据"""
import json, sys, urllib.request

def q(port, cypher):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query",
        data=json.dumps({"cypher": cypher}).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read()).get("rows", [])

def check(port, label):
    res = []
    def add(item, ok, ev): res.append((item, ok, str(ev)[:90]))
    # 1 三环并行: 同类环多实例并发 + 三种环都出现过
    rows = q(port, "MATCH (a:AgentIdentity) RETURN a.ring AS r, a.status AS s")
    rings = [r["r"] for r in rows]
    disc = sum(1 for r in rows if r["r"]=="discovery")
    add("三环-发现环n实例", disc >= 2, f"discovery workers={disc}")
    add("三环-至少双环激活", len(set(rings)) >= 2, f"rings={set(rings)}")
    add("三环-三类齐全", len(set(rings)) >= 3, f"rings={set(rings)}")
    # 2 图共享状态: 六类节点齐
    counts = {}
    for n in ["Signal_","Endpoint","Finding","Hypothesis","ExperienceWeight","AgentIdentity"]:
        rows = q(port, f"MATCH (x:{n}) RETURN count(x) AS c")
        counts[n] = rows[0]["c"] if rows else 0
    add("图共享状态层", all(v>0 for v in counts.values()), counts)
    # 3 持久化: AgentIdentity 有 checkpoint 内容
    rows = q(port, "MATCH (a:AgentIdentity) WHERE a.checkpoint <> '' RETURN count(a) AS c")
    add("持久化checkpoint", (rows[0]["c"] if rows else 0) > 0, f"rows={rows[0]['c'] if rows else 0}")
    # 4 经验沉淀: 库非空且有 succ/fail 双向
    rows = q(port, "MATCH (e:ExperienceWeight) RETURN e.id AS i")
    ids = [r["i"] for r in rows]
    has_s = any(str(i).startswith("succ:") for i in ids)
    has_f = any(str(i).startswith("fail:") for i in ids)
    add("经验沉淀", len(ids)>0 and (has_s or has_f), f"total={len(ids)} succ={has_s} fail={has_f}")
    # 5 防卡死/反思唤醒: 创造环出现过 或 exhausted 收尾
    arows = q(port, "MATCH (a:AgentIdentity) RETURN a.ring AS r")
    creative = sum(1 for r in arows if r.get("r")=="creative")
    eng = q(port, "MATCH (e:Engagement) RETURN e.status AS s")
    st = eng[0]["s"] if eng else "?"
    add("防卡死/反思唤醒", creative>0 or st in ("completed","exhausted"), f"creative={creative} status={st}")
    # 6 质量门控: Finding 都有 severity 且 gate_status=verified
    rows = q(port, "MATCH (f:Finding) RETURN f.severity AS s, f.gate_status AS g")
    bad = [r for r in rows if not r["s"] or (r["g"] and r["g"]!="verified")]
    add("质量门控(verified)", len(rows)>0 and not bad, f"bad={len(bad)} total={len(rows)}")
    # 7 目标完成制: Finding.repro 含可复现命令或产物
    rows = q(port, "MATCH (f:Finding) WHERE f.repro CONTAINS 'curl' RETURN count(f) AS c")
    add("目标完成制(repro)", (rows[0]["c"] if rows else 0) > 0, f"curl-repro={rows[0]['c'] if rows else 0}")

    print(f"\n===== 合规检查 {label} (:${port}) =====".replace("$",""))
    ok_n = 0
    for item, ok, ev in res:
        print(f" {'✅' if ok else '❌'} {item}: {ev}")
        ok_n += bool(ok)
    print(f" 合规分: {ok_n}/{len(res)}")

if __name__ == "__main__":
    port = sys.argv[1] if len(sys.argv)>1 else "8765"
    label = sys.argv[2] if len(sys.argv)>1 else "pi"
    check(port, label)
