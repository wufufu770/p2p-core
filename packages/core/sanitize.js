// sanitize.js — E2 dual-LLM 隔离: worker 读取的不可信页面内容消毒
// OWASP Prompt Injection Prevention Cheat Sheet 推荐的隔离边界
// 原则: 页面中的任何指令性文本一律视为数据, 剥离可执行结构后拼接进 prompt

const CODE_FENCE = /```[a-z]*\n[\s\S]*?```/gi
const SHELL_META = /[`$;&|<>(){}]|\[\[|\]\]/g
const INSTRUCTION_PATTERNS = [
  /ignore\s+(previous|prior|all|above)\s+instructions/gi,
  /forget\s+(everything|your)\s+(else|instructions)/gi,
  /你(的)?(可以|必须|禁止).*(忽略|无视|忘记)/gi,
  /system\s*prompt/gi,
]

/**
 * 消毒不可信内容:
 * - 剥 markdown 代码围栏
 * - 剔除指令性文本(整段)
 * - 剥 shell 元字符
 * - 截断超长文本
 */
export function sanitizeUntrusted(raw, opts = {}) {
  const maxLen = opts.maxLen ?? 1500
  let t = String(raw ?? '')
  t = t.replace(CODE_FENCE, ' [blocked:code_fence] ')
  for (const pat of INSTRUCTION_PATTERNS) {
    t = t.replace(pat, (m) => '[' + 'x'.repeat(Math.min(m.length, 8)) + ']')
  }
  t = t.replace(SHELL_META, (c) => (c === '>' ? '&gt;' : '&lt;'))
  if (t.length > maxLen) t = t.slice(0, maxLen) + '...[truncated]'
  return t
}

/** 从目标响应提取可安全入 prompt 的内容(供 brief 组装层使用) */
export function sanitizeForPrompt(raw) {
  return sanitizeUntrusted(raw)
}