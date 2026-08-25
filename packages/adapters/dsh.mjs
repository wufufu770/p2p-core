// adapters/dsh.mjs — HostAdapter 实现: DeepSeek Harness(dsh) 宿主
// 仅此层允许接触宿主 CLI 与进程 API(契约见 README.md)

import { spawn } from 'node:child_process'
import fs from 'node:fs'

export function createDshAdapter(opts = {}) {
  const HOMEDIR = opts.home ?? '/home/wff/d2d'
  const DSH_BIN = opts.dshBin ?? process.env.P2P_DSH_BIN ?? 'dsh'
  const DSH_HOME_DIR = opts.dshHome ?? process.env.P2P_DSH_HOME ?? `${opts.osHome}/.dsh`
  const EVIDENCE_DIR = opts.evidenceDir ?? `${HOMEDIR}/evidence/workers`
  const liveChildren = new Map()

  function killGroup(pid, sig = 'SIGKILL') {
    try { process.kill(-pid, sig) } catch (e) { console.error('[adapter] killGroup:', e?.message) }
    try { process.kill(pid, sig) } catch {}
  }
  function killAllWorkers() {
    let n = 0
    for (const [, ch] of liveChildren) { if (ch.pid) killGroup(ch.pid, 'SIGTERM'); n++ }
    setTimeout(() => {
      for (const [, ch] of liveChildren) { if (ch.pid && !ch.killed) killGroup(ch.pid) }
      liveChildren.clear()
    }, 3000)
    return n
  }

  return {
    name: 'dsh',
    log: (...a) => console.error('[pentest]', ...a),
    notify: (m) => console.error('[pentest]', m),
    async bootstrap() {},
    spawnWorker({ ring, task }) {
      return new Promise((resolve) => {
        // OS 级兜底 + detached 进程组(#11 组杀)
        const child = spawn('timeout', ['--signal=KILL', '--kill-after=5', '20m', DSH_BIN, '--profile', 'headless', task], {
          cwd: HOMEDIR,
          env: (() => {
            // #32: 剥离宿主凭证, 被注入的 worker 无法伪造经验写入
            const e = { ...process.env, DSH_HOME: DSH_HOME_DIR }
            delete e.P2P_HOST_TOKEN
            return e
          })(),
          stdio: ['ignore', 'pipe', 'pipe'],
          detached: true,
        })
        liveChildren.set(child.pid, child)
        let out = ''
        let settled = false
        const finish = (code) => {
          if (settled) return
          settled = true
          try { fs.mkdirSync(EVIDENCE_DIR, { recursive: true }) } catch (e) { console.error('[adapter] evidence:', e?.message) }
          try { fs.writeFileSync(`${EVIDENCE_DIR}/${Date.now()}-${ring}.log`, out) } catch {}
          resolve({ code, text: out.slice(-2000) })
        }
        const hardTimer = setTimeout(() => { if (child.pid) killGroup(child.pid) }, 20 * 60_000)
        // #30 修复: close 可能因 SIGKILL 竞争不触发 -> 兜底强制 resolve, 杜绝 workers.size 永久卡死
        const settleTimer = setTimeout(() => { killGroup(child.pid ?? 0); finish(null) }, 21 * 60_000)
        child.stdout.on('data', (d) => (out += d.toString()))
        child.stderr.on('data', (d) => (out += d.toString()))
        child.on('close', (code) => {
          clearTimeout(hardTimer)
          clearTimeout(settleTimer)
          for (const [k, c] of liveChildren) if (c === child) liveChildren.delete(k)
          finish(code)
        })
      })
    },
    killAllWorkers,
  }
}
