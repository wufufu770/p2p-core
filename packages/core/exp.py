#!/usr/bin/env python3
"""经验库导出/导入: 跨轮持久化 (reset 不再失忆)
用法: exp.py export 8765 /home/wff/p2p/experience.json
      exp.py import 8766 /home/wff/d2d/experience.json
"""
import json
import sys
import urllib.request


def q(port, cypher, params=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/query",
        data=json.dumps({"cypher": cypher, "params": params or {}}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=8).read())


def export(port, path):
    rows = q(port, "MATCH (e:ExperienceWeight) RETURN e.id AS id, e.pattern AS pattern, e.stack AS stack, e.prior AS prior, e.hits AS hits, e.wins AS wins, e.target_type AS target_type")["rows"]
    out = rows
    json.dump(out, open(path, "w"), ensure_ascii=False, indent=1)
    print(f"exported {len(out)} experience rows -> {path}")


def imp(port, path):
    try:
        rows = json.load(open(path))
    except FileNotFoundError:
        print("no prior experience file, fresh start")
        return
    n = 0
    for e in rows:
        props = ", ".join(
            f"{k}:${k}" for k in e if k != "id"
        )
        cy = f"MERGE (x:ExperienceWeight {{id:$id}}) ON CREATE SET {props} RETURN x.id"
        r = q(port, cy, {"id": e.get("id", "unk"), **{k: v for k, v in e.items() if k != "id"}})
        n += 1
    print(f"imported {n} experience rows from {path}")


if __name__ == "__main__":
    action, port, path = sys.argv[1], sys.argv[2], sys.argv[3]
    {"export": export, "import": imp}[action](int(port), path)
