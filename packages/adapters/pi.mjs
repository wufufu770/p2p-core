// adapters/pi.mjs — HostAdapter 实现: pi-coding-agent 宿主
// 仅此层允许接触宿主 CLI 与进程 API(契约见 README.md)

import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export function createPiAdapter(opts = {}) {
  const HOMEDIR = opts.home ?? '/home/wff/p2p'
  const PI_BIN = opts.piBin ?? process.env.P2P_PI ?? `${HOMEDIR}/pi/node_modules/.bin/pi`
  const P2P_HOME = opts.p2pHome ?? process.env.P2P_HOME ?? `${HOMEDIR}/home`
  const EVIDENCE_DIR = opts.evidenceDir ?? `${HOMEDIR}/evidence/workers`
  const liveChildren = new Map()

  function killGroup(pid, sig = 'SIGKILL') {
    try { process.kill(-pid, sig) } catch {}
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

  let _gateHandler = null
  function wireGate(pi) {
    // pi 官方 tool-call 钩子(types.d.ts L922); deny 形状 { block, reason }
    if (!pi?.on) return
    pi.on('tool_call', async (event) => {
      if (event && typeof event === 'object' && 'input' in event &&
          event.input?.command !== undefined && _gateHandler) {
        const cmd = String(event.input.command)
        const reason = await _gateHandler(cmd)
        if (reason) return { block: true, reason }
      }
      return undefined
    })
  }

  return {
    name: 'pi',
    log: (...a) => console.error('[pentest]', ...a),
    notify: () => {},   // pi 宿主的 notify 由薄壳经 ctx.ui 注入
    /** F4 契约: 门控挂载点 */
    registerGate(pi, handler) {
      _gateHandler = handler
      wireGate(pi)
    },
    async bootstrap() {},
    spawnWorker({ ring, task, timeoutMs }) {
      return new Promise((resolve) => {
        const dir = mkdtempSync(join(tmpdir(), 'p2pc-'))
        const promptFile = join(dir, 'brief.txt')
        writeFileSync(promptFile, task)   // core 已组装完整任务书
        const maxTurns = 25
        const args = ['--mode', 'json', '-p', '--no-session',
                      '--append-system-prompt', promptFile, `Task: ${task}`]
        const osTimeoutSec = Math.ceil((timeoutMs ?? 15 * 60_000) / 1000) + 60
        const child = spawn(
          'timeout',
          [`--signal=KILL`, `--kill-after=5`, `${osTimeoutSec}s`, PI_BIN, ...args],
          {
            cwd: HOMEDIR,
            env: (() => {
              // #32: 剥离宿主凭证
              const e = { ...process.env, HOME: P2P_HOME }
              delete e.P2P_HOST_TOKEN
              return e
            })(),
            stdio: ['ignore', 'pipe', 'pipe'],
            detached: true,
          },
        )
        liveChildren.set(child.pid, child)
        console.error(`[adapter] SPAWN ${ring} wrapper=timeout os=${osTimeoutSec}s pid=${child.pid}`)

        let buf = '', finalText = '', turns = 0, out = ''
        let settled = false
        const finish = (code) => {
          if (settled) return
          settled = true
          try { fs.mkdirSync(EVIDENCE_DIR, { recursive: true }); fs.writeFileSync(`${EVIDENCE_DIR}/${Date.now()}-${ring}.log`, out) } catch {}
          resolve({ code, text: (finalText || out).slice(-2000) })
        }
        const hardTimer = setTimeout(() => { if (child.pid) killGroup(child.pid) }, timeoutMs ?? 15 * 60_000)
        const settleTimer = setTimeout(() => { if (child.pid) killGroup(child.pid); finish(null) }, (timeoutMs ?? 15 * 60_000) + 60_000)

        child.stdout.on('data', (d) => {
          out += d.toString()
          buf += d.toString()
          let idx
          while ((idx = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, idx).trim()
            buf = buf.slice(idx + 1)
            if (!line) continue
            try {
              const ev = JSON.parse(line)
              if (ev.type === 'message_end' && ev.message?.role === 'assistant') {
                turns++
                for (const c of ev.message?.content ?? []) {
                  if (c?.type === 'text') finalText += c.text
                }
                if (turns >= maxTurns && !child.killed) killGroup(child.pid)
              }
            } catch {}
          }
        })
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
