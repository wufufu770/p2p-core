# HostAdapter 契约（调度器统一的前置规范）

## 目标
把 p2p(index.ts/rings.ts ~700行) 与 d2d(index.js 615行) 中重复的链式调度/角色/handoff/run-log
逻辑合并为 `packages/core/scheduler.js`（唯一副本），宿主差异收敛到两个薄适配器。

## 接口（4+1 原语）
```js
// adapter 必须实现:
export default {
  name: 'pi' | 'dsh',
  async bootstrap() {},                       // 宿主专属 import(如 child_process)、路径解析
  spawnWorker({ task, timeoutMs })            // -> Promise<{ code, text }>  内部必须含:
  ,                                           //   OS timeout --signal=KILL 包装 + detached 进程组
  registerGate(handler) {}                    // handler(bashCmd, resolveEngagement) => {block?, reason?}
  registerCommand(name, description, fn) {}   // 宿主命令面(或测试发射器的 cmds 收集器)
}
```

## core/scheduler.js 导出
```js
apply(adapter, { graphdUrl, runsBase, rolesDir, gapHintsEnv }) -> {
  startEngagement(target, scope, instances),  // 含 #14 等待终态
  stopAll(),                                  // killAllWorkers 组杀
  statusText(),
}
```

## 迁移时的行为保真清单（缺一不可）
- [ ] 三环唤醒条件(#12 verified判据 / #16假设消费优先 / #19终态闭环)
- [ ] 心跳30min窗口(#22) 与 AgentIdentity checkpoint 写入(Wave0 兑现版)
- [ ] 角色选角: discovery按chain / deep按signal_affinity / creative双人格轮替
- [ ] handoff: artifacts/<wid>/{evidence,handoff}.md + context_refs 注入
- [ ] run-log.jsonl 调度器单写入者全事件流
- [ ] 经验拉普拉斯先验 prior=(wins+1)/(hits+2) 与 harvest 回写
- [ ] GAP_HINTS 注入(P2P_GAP_HINTS)
- [ ] worker brief 全部硬规则 A-F + 表白名单 + DDL禁令提示

## 切换验收
同一靶场(vuln-bank)上：统一版 vs 旧实现 各跑 2 轮 range_run，
eval_profile 分数差 <10%，compliance_check ≥ 旧版得分，方可替换消费仓实现。
