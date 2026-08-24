#!/usr/bin/env python3
"""eval_profile.py v2 <graph_port> <profile_json> -> 基于靶场档案的评估
v2: 误报判定用 title+category+repro 三字段; 覆盖判定文本池含 category。
"""
import json, sys, urllib.request

def q(port, cypher):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query",
        data=json.dumps({"cypher": cypher}).encode(), headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read()).get("rows", [])

def main():
    port, prof_file = int(sys.argv[1]), sys.argv[2]
    P = json.load(open(prof_file))
    # ---- 文本池(Finding 三字段 / Signal / checkpoint) ----
    findings, texts = [], []
    for r in q(port, "MATCH (f:Finding) RETURN f.id AS id, f.title AS a, f.category AS c, f.repro AS b"):
        t = f"{r.get('a') or ''} | {r.get('c') or ''} | {r.get('b') or ''}".lower()
        findings.append({"id": r["id"], "text": t})
        texts.append(t)
    for cy in ["MATCH (s:Signal_) RETURN s.id AS a, s.evidence AS b",
               "MATCH (a:AgentIdentity) RETURN a.checkpoint AS a, a.checkpoint AS b"]:
        for r in q(port, cy):
            texts.append((str(r.get("a") or "") + " | " + str(r.get("b") or "")).lower())
    blob = "\n".join(texts)
    # ---- 类覆盖 ----
    cov = {}
    for cls, spec in P["classes"].items():
        kws = [k.lower() for k in spec["kw"]] + [cls.lower()]
        cov[cls] = any(k in blob for k in kws)
    covered, total = sum(cov.values()), len(P["classes"])
    # ---- artifacts ----
    arts = {}
    for a in P.get("artifacts", []):
        kws = [k.lower() for k in a["kw"]]
        arts[a["id"]] = any(k in blob for k in kws)
    art_n = sum(arts.values())
    # ---- 误报: title+category+repro 均不含任何已知类关键词/类名 -> FP ----
    all_kws = set(k.lower() for s in P["classes"].values() for k in s["kw"])
    all_kws |= {c.lower() for c in P["classes"]}
    fps = [f["id"] for f in findings if f["id"] and not any(k in f["text"] for k in all_kws)]
    passed = (covered / max(total, 1) >= 0.8) and (art_n == len(P.get("artifacts", []))) and not fps
    print(json.dumps({"covered": f"{covered}/{total}", "coverage_pct": round(100*covered/max(total,1)),
                      "class_detail": cov, "artifacts": f"{art_n}/{len(arts)}", "artifact_detail": arts,
                      "false_positives": fps, "PASS": passed}, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
