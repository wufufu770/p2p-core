#!/usr/bin/env python3
"""graphd 机械门负例集 — 不起服务, 直接对门逻辑做单元级断言。
门逻辑在 app.py 的 do_POST 内联, 此处以等价正则复刻并锁定行为(防再次双重转义死门)。
"""
import re
import pytest

# ---- 与 graphd/app.py 保持同步的门规则 ----
EMPTY_TITLE = re.compile(r"title\s*:")
DDL = re.compile(r"\b(CREATE|DROP)\s+(NODE\s+|REL\s+)?TABLE", re.I)
JUNK = ["no rate limit", "missing rate limit", "lack of rate limiting",
        "rate limiting disabled", "限速缺失", "未限速",
        "security header", "安全头", "cors configuration",
        "sourcemap", "版本号指纹", "self-xss", "tls warning"]
TITLE_RE = re.compile(r"title\s*:\s*[\"'](.*?)[\"']")


def empty_title_rejected(cypher: str) -> bool:
    m = EMPTY_TITLE.search(cypher + " ")
    if not m or "Finding" not in cypher or "CREATE" not in cypher.upper():
        return False
    tail = cypher[m.end():].lstrip()[:2]
    return tail[0:1] in (")", ",") or tail in ('""', "''")


def ddl_rejected(cypher: str) -> bool:
    return bool(DDL.search(cypher))


def junk_rejected(cypher: str) -> bool:
    if "Finding" not in cypher or "CREATE" not in cypher.upper():
        return False
    t = TITLE_RE.search(cypher)
    if not t:
        return False
    tv = t.group(1).lower()
    return any(j in tv for j in JUNK)


# ---- #21 空标题门 ----
def test_empty_title_double_quote():
    assert empty_title_rejected('CREATE (f:Finding {id:"a", title:"", severity:"low"})')

def test_empty_title_single_quote():
    assert empty_title_rejected("CREATE (f:Finding {id:'a', title:'', severity:'low'})")

def test_no_title_at_all_followed_by_comma():
    assert empty_title_rejected("CREATE (f:Finding {id:'a', title:, severity:'low'})")

def test_real_title_passes_empty_gate():
    assert not empty_title_rejected('CREATE (f:Finding {id:"a", title:"XSS in search", s:1})')

def test_regex_is_alive_not_double_escaped():
    """锁定历史缺陷: 双重转义的 title\\\\s* 永不匹配"""
    dead = re.compile(r"title\\s*:")
    assert not dead.search("CREATE (f:Finding {title:''})")
    assert EMPTY_TITLE.search("CREATE (f:Finding {title:''})")

# ---- #18 DDL 禁令 ----
@pytest.mark.parametrize("cypher", [
    "CREATE NODE TABLE Evil(id STRING)",
    "DROP TABLE Signal_",
    "create node table x(id string)",
])
def test_ddl_variants_rejected(cypher):
    assert ddl_rejected(cypher)

@pytest.mark.parametrize("cypher", [
    "CREATE (f:Finding {id:'a', title:'users table dump', severity:'low'})",
    "MATCH (s:Signal_) RETURN count(s)",
])
def test_normal_writes_pass_ddl(cypher):
    assert not ddl_rejected(cypher)

# ---- #24 垃圾洞清单门 ----
@pytest.mark.parametrize("title", [
    "Login has no rate limit",
    "Missing security header X-Frame-Options",
    "CORS configuration allows all origins",
])
def test_junk_titles_rejected(title):
    assert junk_rejected(f'CREATE (f:Finding {{id:"j", title:"{title}", severity:"low"}})')

@pytest.mark.parametrize("title", [
    "SQL injection in login bypasses auth",
    "BOLA in payment history access",
    "JWT none-algorithm admin forge",
])
def test_real_titles_pass_junk_gate(title):
    assert not junk_rejected(f'CREATE (f:Finding {{id:"r", title:"{title}", severity:"high"}})')

# ---- scope 启发式(写操作 URL 必须在 127.0.0.1/localhost) ----
SCOPE_OK = {"127.0.0.1", "localhost"}
URL = re.compile(r"https?://[A-Za-z0-9.\-]+")

def url_scope_violation(cypher: str) -> bool:
    if re.search(r"\b(CREATE|SET|MERGE|DELETE)\b", cypher):
        hosts = {u.split("://")[1].lower() for u in URL.findall(cypher)}
        return any(h not in SCOPE_OK for h in hosts)
    return False

def test_out_of_scope_url_in_write_rejected():
    assert url_scope_violation("SET (e:Engagement {target:'http://evil.example.com/'})")

def test_in_scope_url_passes():
    assert not url_scope_violation("SET (e:Engagement {target:'http://127.0.0.1:8081/'})")
