#!/usr/bin/env bash
# sync-out.sh — 从本仓(p2p-core 单一事实源)分发权威副本到消费仓
# 消费仓(d2d/p2p)不得直接修改以下文件; 改动必须先落本仓再分发。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
D2D="${D2D_ROOT:-$HOME/d2d}"
P2P="${P2P_ROOT:-$HOME/p2p}"

echo "[sync] graphd -> 两仓"
cp "$ROOT/packages/graphd/app.py" "$D2D/graphd/app.py"
cp "$ROOT/packages/graphd/app.py" "$P2P/graphd/app.py"

echo "[sync] roles -> d2d 插件"
mkdir -p "$D2D/plugin/pentest-dsh/roles"
cp "$ROOT"/packages/core/roles/*.json "$D2D/plugin/pentest-dsh/roles/"

echo "[sync] SKILL.md 方法论 -> 两仓"
cp "$ROOT/packages/core/skills/SKILL.md" "$D2D/home/.dsh/skills/pentest/SKILL.md"
mkdir -p "$P2P/home/.pi/agent/skills/pentest"
cp "$ROOT/packages/core/skills/SKILL.md" "$P2P/home/.pi/agent/skills/pentest/SKILL.md"

echo "[sync] 评测与合规工具 -> d2d"
cp "$ROOT/packages/core/eval_profile.py" "$ROOT/packages/core/compliance_check.py" \
   "$ROOT/packages/core/exp.py" "$ROOT/packages/core/range_inspect.py" "$D2D/"

echo "[sync] 门函数测试 -> 两仓"
mkdir -p "$D2D/tests"
cp "$ROOT/tests/test_graphd_gates.py" "$D2D/tests/"

echo "[sync] 完成。消费仓各自 commit+push 固化本次分发。"