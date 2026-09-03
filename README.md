# ⚠️ 本仓库已归档（2026-09-04），不再维护

**归档原因**：「宿主无关内核 + `sync-out.sh` 确定性分发」的双宿主（pi / dsh）策略已收敛——实测 **dsh + [d2d](https://github.com/wufufu770/d2d)** 的组合在调度效率、功能完备度与易用性上全面优于 pi + p2p，开发全面转入 d2d 仓，「单一事实源」职责由 d2d 接续：本仓核心（scheduler / graphd / 角色库）的血统在 d2d 的 `plugin/pentest-dsh/` 与 `graphd/` 中延续演化。

**迁移注意**：自 2026-08-26（审查v3）起，d2d 侧已积累大量**未回灌本仓**的演化——candidate 积压水位仲裁（R5）、进程内子 agent 后端（P2P_INPROCESS）、多 engagement 并行门、W2 自动分诊 / W3 经验沉淀闭环、面板 FindingsView 等。**请勿以本仓内容推断 d2d 现状**，一切以 d2d 仓库为准。

本仓保留为 2026-08-26 时点的历史快照，issue / PR 不再受理。

---

# p2p-core — 三环并行渗透测试的宿主无关内核

单一事实源(Source of Truth)。p2p(pi宿主) 与 d2d(dsh宿主) 的共享逻辑全部在此演化,
经 `packages/tools/sync-out.sh` 确定性分发到两个消费仓。

## 布局
- packages/graphd/     Kuzu 单写者 sidecar(唯一副本, 双仓消费)
- packages/core/       角色库 / 方法论SKILL / 评测与合规工具 / 调度内核
- adapters/            HostAdapter 实现(pi.ts / dsh.js) — 仅此层允许接触宿主 API
- plugins/             薄插件壳(装载器)
- tests/               门函数负例集(pytest)

## 不变式
1. 单写者: 所有状态变更经 graphd(或结构化写端点)
2. 机械门下沉: 能 schema 校验的不用正则, 能连接层拦的不拦字符串
3. 宿主无关内核: 业务逻辑禁止 import 宿主 API
4. 声明即契约: README 每条架构声明在 compliance_check 有对应机读检查项
