#!/usr/bin/env python3
"""eval_union.py <profile.json> <port:port:...> — 多车道 union 计分
合并 N 个 graphd 实例的 Finding/Signal 文本池后按档案分类; 输出 union 与分车道明细。
PASS = union 覆盖≥80% 且 artifacts 全拿 且 零误报(以 union 池判定)。
"""
import json, sys, urllib.request

def q(port, cypher):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query",
        data=json.dumps({"cypher": cypher}).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read()).get("rows", [])

def main():
    prof_file = sys.argv[1]
    ports = sys.argv[2].split(":")
    P = json.load(open(prof_file))
    all_kws = set(k.lower() for s in P["classes"].values() for k in s["kw"]) | {c.lower() for c in P["classes"]}

    pool_texts, per_lane = [], {}
    fp_seen = {}
    for port in ports:
        texts = []
        for r in q(int(port), "MATCH (f:Finding) RETURN f.id AS id, f.title AS a, f.category AS c, f.repro AS b"):
            t = f"{r.get('a') or ''} | {r.get('c') or ''} | {r.get('b') or ''}".lower()
            fid = str(r.get("id") or "")
            texts.append(t)
            hit = any(k in t for k in all_kws)
            if not hit and fid and fid != "None":
                fp_seen[f"{port}:{fid}"] = t[:70]
        for cy in ["MATCH (s:Signal_) RETURN s.id AS a, s.evidence AS b",
                   "MATCH (a:AgentIdentity) RETURN a.checkpoint AS a, a.checkpoint AS b"]:
            for r in q(int(port), cy):
                t = (str(r.get("a") or "") + "|" + str(r.get("b") or "")).lower()
                texts.append(t)
        cov = {}
        for cls, spec in P["classes"].items():
            kws = [k.lower() for k in spec["kw"]] + [cls.lower()]
            cov[cls] = any(k in "\n".join(texts) for k in kws)
        arts = {}
        for a in P.get("artifacts", []):
            kws = [k.lower() for k in a["kw"]]
            arts[a["id"]] = any(k in "\n".join(texts) for k in kws)
        per_lane[port] = {
            "covered": sum(cov.values()), "total": len(P["classes"]),
            "artifacts": sum(arts.values()), "classes": [c for c, v in cov.items() if v],
        }
        pool_texts += texts

    blob = "\n".join(pool_texts)
    cov_u, art_u = {}, {}
    for cls, spec in P["classes"].items():
        kws = [k.lower() for k in spec["kw"]] + [cls.lower()]
        cov_u[cls] = any(k in blob for k in kws)
    for a in P.get("artifacts", []):
        kws = [k.lower() for k in a["kw"]]
        art_u[a["id"]] = any(k in blob for k in kws)
    covered_u, total = sum(cov_u.values()), len(P["classes"])
    art_n, art_t = sum(art_u.values()), len(art_u)
    # FP 判定基于 union 池去重(按标题签名)
    seen_sig, fps = set(), []
    for fid, t in sorted(fp_seen.items()):
        sig = "".join(sorted(set(t.split())))
        if sig in seen_sig: continue
        seen_sig.add(sig)
        if not any(k in t for k in all_kws): fps.append(f"{fid}: {t}")
    passed = (covered_u / max(total, 1) >= 0.8) and (art_n == art_t) and not fps
    print(json.dumps({
        "union_covered": f"{covered_u}/{total}", "coverage_pct": round(100 * covered_u / max(total, 1)),
        "union_artifacts": f"{art_n}/{art_t}",
        "uncovered": [c for c, v in cov_u.items() if not v],
        "missing_artifacts": [a for a, v in art_u.items() if not v],
        "fps": fps,
        "per_lane": {p: f"{d['covered']}/{d['total']}+{d['artifacts']}art" for p, d in per_lane.items()},
        "PASS": passed,
    }, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
