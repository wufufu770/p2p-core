#!/usr/bin/env bash
# restart-graphds.sh — 可靠的双 graphd 重启(幂等, 等待健康)
set -u
kill_all() {
  for p in $(pgrep -f "python3 app\.py"); do kill -9 "$p" 2>/dev/null; done
  sleep 1
}
wait_health() { # port
  for _ in $(seq 1 15); do
    curl -s --max-time 2 "http://127.0.0.1:$1/health" | grep -q '"ok"' && return 0
    sleep 2
  done
  echo "FAIL: :$1 未就绪"; return 1
}
kill_all
( setsid nohup /home/wff/p2p/graphd/start.sh >> /home/wff/p2p/graphd/graphd.log 2>&1 < /dev/null & ) 
sleep 2
( setsid nohup /home/wff/d2d/graphd/start.sh >> /home/wff/d2d/graphd/graphd.log 2>&1 < /dev/null & )
wait_health 8765 && echo "✅ 8765 (p2p)" || exit 1
wait_health 8766 && echo "✅ 8766 (d2d)" || exit 1
