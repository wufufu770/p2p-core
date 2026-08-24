#!/usr/bin/env python3
"""graphd - Kuzu 单写者 sidecar。三环+插件全部经 HTTP 读写图,规避多进程锁。
stdlib only (kuzu 除外). GET /health POST /query POST /reset
"""
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 可移植性: DB 默认落在脚本同目录(每仓天然隔离); 端口由各仓 start.sh 钉定
DB_PATH = os.environ.get("P2P_GRAPH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "kuzu_db"))
PORT = int(os.environ.get("P2P_GRAPH_PORT", "8766"))

import kuzu

_lock = threading.Lock()
_db = None


def db():
    global _db
    if _db is None:
        parent = os.path.dirname(DB_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        _db = kuzu.Database(DB_PATH)
        conn = kuzu.Connection(_db)
        init_schema(conn)
    return _db


SCHEMA = [
    "CREATE NODE TABLE IF NOT EXISTS Engagement(name STRING, target STRING, scope STRING, auth STRING, status STRING, created_at STRING, PRIMARY KEY(name))",
    "CREATE NODE TABLE IF NOT EXISTS Endpoint(id STRING, url STRING, param STRING, method STRING, tech STRING, business_chain STRING, coverage_votes INT64 DEFAULT 0, exhausted BOOL DEFAULT false, PRIMARY KEY(id))",
    "CREATE NODE TABLE IF NOT EXISTS Signal_(id STRING, type STRING, weight DOUBLE DEFAULT 1.0, status STRING DEFAULT 'open', evidence STRING, ts STRING, ring STRING, PRIMARY KEY(id))",
    "CREATE NODE TABLE IF NOT EXISTS Hypothesis(id STRING, text STRING, strategy STRING, status STRING DEFAULT 'open', ts STRING, PRIMARY KEY(id))",
    "CREATE NODE TABLE IF NOT EXISTS Finding(id STRING, title STRING, severity STRING, cvss DOUBLE DEFAULT 0.0, evidence_dir STRING, repro STRING, category STRING DEFAULT 'vuln', gate_status STRING DEFAULT 'candidate', ts STRING, PRIMARY KEY(id))",
    "CREATE NODE TABLE IF NOT EXISTS ExperienceWeight(id STRING, pattern STRING, stack STRING, prior DOUBLE DEFAULT 1.0, hits INT64 DEFAULT 0, wins INT64 DEFAULT 0, target_type STRING DEFAULT 'web', PRIMARY KEY(id))",
    "CREATE NODE TABLE IF NOT EXISTS AgentIdentity(worker_id STRING, ring STRING, chain STRING, status STRING, checkpoint STRING, todo STRING, updated_at STRING, PRIMARY KEY(worker_id))",
    "CREATE REL TABLE IF NOT EXISTS AT(FROM Signal_ TO Endpoint)",
    "CREATE REL TABLE IF NOT EXISTS CONFIRMS(FROM Finding TO Signal_)",
    "CREATE REL TABLE IF NOT EXISTS SUGGESTS(FROM Hypothesis TO Endpoint)",
    "CREATE REL TABLE IF NOT EXISTS DERIVED_FROM(FROM Signal_ TO Signal_)",
    "CREATE REL TABLE IF NOT EXISTS PRIOR_FOR(FROM ExperienceWeight TO Signal_)",
]


def init_schema(conn):
    for q in SCHEMA:
        try:
            conn.execute(q)
        except Exception as e:
            if "already exists" not in str(e):
                raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True, "db": DB_PATH})
        else:
            self._send(404, {"error": "unknown"})

    def _auth(self, level):
        """level='host': 需 HOST_TOKEN; level='worker': WORKER 或 HOST 均可。
        未配置对应 token 时放行(向后兼容 range 模式)。"""
        host = os.environ.get("P2P_HOST_TOKEN", "")
        worker = os.environ.get("P2P_WORKER_TOKEN", "")
        got = self.headers.get("X-Auth", "")
        if level == "host":
            return (not host) or got == host
        return (not worker) or got in (worker, host) or bool(host) and got == host

    def do_POST(self):

        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            return self._send(400, {"ok": False, "error": f"bad json: {e}"})
        # token 认证(未配置 P2P_TOKEN 时放行)
        tok = os.environ.get("P2P_TOKEN", "")
        if tok and self.headers.get("X-Auth") != tok:
            return self._send(401, {"error": "unauthorized"})
        # ---- 结构化写端点: 参数校验替代内联 cypher 正则扫描(根治 #21 死门与 params 旁路) ----

        if self.path in ("/write/finding", "/write/signal", "/write/hypothesis"):

            if not self._auth("worker"):
                return self._send(401, {"ok": False, "error": "unauthorized for structured writes"})
            # 注意: req 已由 do_POST 开头解析, 此处严禁重复 rfile.read(#27 双读挂死)
            with _lock:
                try:
                    conn = kuzu.Connection(db())
                    if self.path == "/write/finding":
                        title = str(req.get("title") or "").strip()
                        if not title:
                            return self._send(400, {"ok": False, "error": "title required"})
                        tl = title.lower()
                        junk = ["no rate limit", "missing rate limit", "lack of rate limiting",
                                "rate limiting disabled", "限速缺失", "未限速",
                                "security header", "安全头", "cors configuration",
                                "sourcemap", "版本号指纹", "self-xss", "tls warning"]
                        if any(j in tl for j in junk):
                            return self._send(400, {"ok": False, "error": "garbage-listed finding rejected"})
                        conn.execute(
                            "CREATE (f:Finding {id:$id, title:$title, severity:$sev, cvss:$cvss, "
                            "evidence_dir:$edir, repro:$repro, category:$cat, gate_status:'candidate', ts:$ts})",
                            parameters={"id": str(req.get("id") or f"f-{int(time.time()*1000)}"),
                                        "title": title, "sev": str(req.get("severity") or "medium"),
                                        "cvss": float(req.get("cvss") or 5.0),
                                        "edir": str(req.get("evidence_dir") or ""),
                                        "repro": str(req.get("repro") or ""),
                                        "cat": str(req.get("category") or "vuln"),
                                        "ts": str(req.get("ts") or datetime.now(timezone.utc).isoformat())})
                    elif self.path == "/write/signal":
                        conn.execute(
                            "CREATE (s:Signal_ {id:$id, type:$t, weight:$w, status:$st, evidence:$ev, ts:$ts, ring:$ring})",
                            parameters={"id": str(req.get("id") or f"s-{int(time.time()*1000)}"),
                                        "t": str(req.get("type") or "unknown"),
                                        "w": float(req.get("weight") or 1.0),
                                        "st": str(req.get("status") or "open"),
                                        "ev": str(req.get("evidence") or "")[:2000],
                                        "ts": str(req.get("ts") or datetime.now(timezone.utc).isoformat()),
                                        "ring": str(req.get("ring") or "discovery")})
                    else:
                        conn.execute(
                            "CREATE (h:Hypothesis {id:$id, text:$txt, strategy:$strat, status:'open', ts:$ts})",
                            parameters={"id": str(req.get("id") or f"h-{int(time.time()*1000)}"),
                                        "txt": str(req.get("text") or "")[:1500],
                                        "strat": str(req.get("strategy") or "inversion"),
                                        "ts": str(req.get("ts") or datetime.now(timezone.utc).isoformat())})
                except Exception as e:
                    return self._send(500, {"ok": False, "error": str(e)[:200]})
            return self._send(200, {"ok": True})

        # 经验库写权限收归 host(防被注入的 worker 给自己刷经验权重)
        if re.search(r"ExperienceWeight", req.get("cypher", "")) and re.search(r"\b(CREATE|SET|MERGE|DELETE)\b", req.get("cypher", "")):
            if not self._auth("host"):
                return self._send(403, {"ok": False, "error": "ExperienceWeight mutations require host token"})
        cypher_raw = req.get("cypher", "")
        # 缺陷#21: Finding 数据质量门 —— 无标题的 Finding 一律拒收(模板垃圾防线)
        if "Finding" in cypher_raw and "CREATE" in cypher_raw.upper():
            import re as _t
            m = _t.search(r"title\s*:", cypher_raw + " ")
            if m:
                tail = cypher_raw[m.end():].lstrip()[:2]
                if tail[0:1] in (")", ",") or tail in ('""', "''"):
                    return self._send(400, {"ok": False, "error": "Finding.title must be non-empty"})
        # 缺陷#24: 垃圾洞清单机械门 —— 与 SKILL.md 铁律同源的拒绝模式
        if "Finding" in cypher_raw and "CREATE" in cypher_raw.upper():
            import re as _g
            t = _g.search(r"title\s*:\s*[\"'](.*?)[\"']", cypher_raw)
            if t:
                tv = t.group(1).lower()
                junk = ["no rate limit", "missing rate limit", "lack of rate limiting",
                        "rate limiting disabled", "\u9650\u901f\u7f3a\u5931", "\u672a\u9650\u901f",
                        "security header", "\u5b89\u5168\u5934", "cors configuration",
                        "sourcemap", "\u7248\u672c\u53f7\u6307\u7eb9", "self-xss", "tls warning"]
                if any(j in tv for j in junk):
                    return self._send(400, {"ok": False, "error": "garbage-listed finding rejected: " + tv[:60]})
        # 缺陷#18: DDL 禁令 —— schema 固定, 运行期禁止建/删表(worker 漂移防线)
        import re as _ddl
        if _ddl.search(r"\b(CREATE|DROP)\s+(NODE\s+|REL\s+)?TABLE", cypher_raw, _ddl.I):
            return self._send(403, {"ok": False, "error": "DDL forbidden at runtime (schema is fixed)"})
        # 纵深防御: 写操作中的 URL host 必须在活跃 scope 内
        import re as _re
        if _re.search(r"\b(CREATE|SET|MERGE|DELETE)\b", cypher_raw):
            urls = _re.findall(r"https?://[A-Za-z0-9.\-]+", cypher_raw)
            hosts = set()
            for u in urls:
                h = u.split("://")[1].lower()
                if h not in ("127.0.0.1", "localhost"):
                    hosts.add(h)
            if hosts:
                with _lock:
                    try:
                        c = kuzu.Connection(db())
                        r = c.execute("MATCH (e:Engagement) WHERE e.status = 'active' RETURN e.scope")
                        scope = ""
                        while r.has_next():
                            scope += str(r.get_next()[0] or "") + ","
                        allowed = [s.strip().lower() for s in scope.split(",") if s.strip()]
                        for h in hosts:
                            if not any(h == a or h.endswith("." + a) for a in allowed):
                                return self._send(403, {"error": f"scope violation at graphd layer: {h}"})
                    except Exception:
                        pass
        if self.path == "/query":
            cypher = req.get("cypher", "").strip()
            params = req.get("params") or {}
            if not cypher:
                return self._send(400, {"error": "empty cypher"})
            with _lock:
                try:
                    conn = kuzu.Connection(db())
                    res = conn.execute(cypher, params)
                    rows = []
                    while res.has_next():
                        rows.append(res.get_next())
                    cols = res.get_column_names()
                    data = []
                    for r in rows:
                        data.append({cols[i]: _jsonify(r[i]) for i in range(len(cols))})
                    return self._send(200, {"ok": True, "rows": data})
                except Exception as e:
                    return self._send(400, {"ok": False, "error": str(e)})
        elif self.path == "/reset":
            tok2 = os.environ.get("P2P_TOKEN", "")
            if not tok2 or self.headers.get("X-Auth") != tok2:
                return self._send(403, {"error": "/reset disabled (token required); use reset-graphs.sh instead"})
            global _db
            with _lock:
                _db = None
                import shutil
                shutil.rmtree(DB_PATH, ignore_errors=True)
            return self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "unknown"})


def _jsonify(v):
    if isinstance(v, (int, float, str, bool)) or v is None:
        return v
    return str(v)


if __name__ == "__main__":
    db()  # 初始化 schema
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[graphd] listening :{PORT} db={DB_PATH}", flush=True)
    srv.serve_forever()
