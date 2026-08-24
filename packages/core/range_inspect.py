#!/usr/bin/env python3
"""R1+ 巡检器: python3 inspect.py <port> <label> <eng-prefix>"""
import json
import sys
import urllib.request

port, label, prefix = sys.argv[1], sys.argv[2], sys.argv[3]


def q(cypher):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/query",
        data=json.dumps({"cypher": cypher}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=8).read()).get("rows", [])


print(f"── {label} (:${port}) ──".replace("$", ""))
for r in q(f"MATCH (a:AgentIdentity) WHERE a.worker_id CONTAINS '{prefix}' RETURN a.ring AS ring, a.status AS st"):
    print("  worker:", r)
for cy, name in [
    ("MATCH (x:Endpoint) RETURN count(x) AS c", "endpoints"),
    ("MATCH (s:Signal_) WHERE s.weight>=3 AND s.status='open' RETURN count(s) AS c", "high_weight_open"),
    ("MATCH (s:Signal_) WHERE s.status='refuted' OR s.status='pruned' RETURN count(s) AS c", "refuted_pruned"),
    ("MATCH (f:Finding) RETURN count(f) AS c", "findings"),
    ("MATCH (h:Hypothesis) RETURN count(h) AS c", "hypotheses"),
    ("MATCH (e:ExperienceWeight) RETURN count(e) AS c", "experience"),
]:
    rows = q(cy)
    print(f"   {name}: {rows[0]['c'] if rows else '?'}")
top = q("MATCH (s:Signal_) WHERE s.weight>=4 RETURN s.id AS i, s.weight AS w, s.evidence AS ev ORDER BY s.weight DESC LIMIT 3")
for r in top:
    print(f"   sig w={r['w']} {r['i']}: {str(r.get('ev'))[:70]}")
