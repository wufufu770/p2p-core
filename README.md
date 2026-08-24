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
