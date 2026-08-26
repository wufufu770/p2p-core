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
echo "[sync] 统一调度内核 + dsh适配器 -> d2d 插件"
cp "$ROOT/packages/core/scheduler.js" "$D2D/plugin/pentest-dsh/scheduler.js"
cp "$ROOT/packages/core/sanitize.js" "$D2D/plugin/pentest-dsh/sanitize.js"
cp "$ROOT/packages/adapters/dsh.mjs" "$D2D/plugin/pentest-dsh/adapter-dsh.mjs"
cp "$ROOT/plugins/pentest-dsh/index.js" "$D2D/plugin/pentest-dsh/index.js"

echo "[sync] 统一调度内核 + pi适配器 + 薄壳 -> p2p"
PENT="$P2P/home/.pi/agent/extensions/pentest"
mkdir -p "$PENT/roles"
cp "$ROOT/packages/core/scheduler.js" "$PENT/scheduler.js"
cp "$ROOT/packages/core/sanitize.js" "$PENT/sanitize.js"
cp "$ROOT/packages/adapters/pi.mjs" "$PENT/adapter-pi.mjs"
cp "$ROOT/plugins/pentest-pi/index.ts" "$PENT/index.ts"
cp "$ROOT"/packages/core/roles/*.json "$PENT/roles/"
cp "$ROOT/packages/core/validator.js" "$ROOT/packages/core/planner.js" "$ROOT/packages/core/report.mjs" "$D2D/plugin/pentest-dsh/" 2>/dev/null || true
cp "$ROOT/packages/core/validator.js" "$ROOT/packages/core/planner.js" "$ROOT/packages/core/report.mjs" "$PENT/" 2>/dev/null || true

echo "[sync] N4 一致性门禁: core 与消费仓 diff 核验"
DRIFT=0
check() { # base_file consumer_file
  if [ -f "$1" ] && [ -f "$2" ] && ! diff -q "$1" "$2" >/dev/null 2>&1; then
    echo "  ❌ DRIFT: $1  ≠  $2"
    DRIFT=1
  fi
}
check "$ROOT/packages/graphd/app.py"        "$D2D/graphd/app.py"
check "$ROOT/packages/graphd/app.py"        "$P2P/graphd/app.py"
check "$ROOT/packages/core/scheduler.js"    "$D2D/plugin/pentest-dsh/scheduler.js"
check "$ROOT/packages/core/scheduler.js"    "$P2P/home/.pi/agent/extensions/pentest/scheduler.js"
check "$ROOT/packages/core/validator.js"    "$D2D/plugin/pentest-dsh/validator.js"
check "$ROOT/packages/core/validator.js"    "$P2P/home/.pi/agent/extensions/pentest/validator.js"
check "$ROOT/packages/core/planner.js"      "$D2D/plugin/pentest-dsh/planner.js"
check "$ROOT/packages/core/planner.js"      "$P2P/home/.pi/agent/extensions/pentest/planner.js"
check "$ROOT/packages/core/report.mjs"      "$D2D/plugin/pentest-dsh/report.mjs"
check "$ROOT/packages/core/report.mjs"      "$P2P/home/.pi/agent/extensions/pentest/report.mjs"
check "$ROOT/packages/core/eval_profile.py" "$D2D/eval_profile.py"
check "$ROOT/packages/core/compliance_check.py" "$D2D/compliance_check.py"
for r in "$ROOT"/packages/core/roles/*.json; do
  [ -f "$r" ] || continue
  if ! diff -q "$r" "$D2D/plugin/pentest-dsh/roles/$(basename "$r")" >/dev/null 2>&1; then
    echo "  ❌ DRIFT: roles/$(basename "$r")  ≠  d2d"
    DRIFT=1
  fi
done
if [ "$DRIFT" = "1" ]; then
  echo "[sync] ❌ 一致性门禁未过: 消费仓存在漂移, 请先修复再推送"
  exit 1
else
  echo "[sync] ✅ 一致性门禁通过: core 与全部消费仓一致"
fi
