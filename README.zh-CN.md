# SourceQuorum

SourceQuorum 是一个本地、deterministic fail-closed comparison 工具：它从显式提供的本地来源生成并检查小型研究发布物。

## 证据边界

本 Phase A 仓库只包含标记为 synthetic 的 `synthetic.inventory.v1` 示例。经过测试的边界会在显式 candidate 与独立 crosscheck 的已声明本地记录一致时接受结果；它不获取数据、不证明现实中的来源独立性、不保证数据真实性，也不验证投资结论。

接受后可发布内容寻址且 SourceQuorum 不覆盖既有目标的本地制品。它可检测事后变化，不是文件系统写保护：拥有写权限的人仍可改动文件，但验证可发现不一致的已存储发布物。

默认验证只检查已存储发布物，不会重算未随发布物保存的原始来源字节。来源重放需要提供全部原始来源目录；它使用 manifest 固化的 `evaluated_at` 重新构建发布物，并要求 release ID 与四个发布成员逐字节一致。两种模式均只读、离线。

## 五分钟 Quickstart

`--output` 指向的根目录必须预先存在。以下命令以仓库根目录（`.`）为输出根，因此发布物位于 `./releases/<release-id>`；`<release-id>` 来自 publish 输出。

```text
sourcequorum check --policy examples/inventory/policy.json \
  --source examples/inventory/candidate \
  --source examples/inventory/crosscheck \
  --at 2040-01-15T00:05:00+00:00 --json

sourcequorum publish --policy examples/inventory/policy.json \
  --source examples/inventory/candidate \
  --source examples/inventory/crosscheck \
  --at 2040-01-15T00:05:00+00:00 \
  --output . --commit --json

sourcequorum verify ./releases/<release-id> --json

sourcequorum verify ./releases/<release-id> \
  --source examples/inventory/candidate \
  --source examples/inventory/crosscheck --json
```

三个用户工作流动作分别是 Evaluate（`check`）、Publish（`publish --commit --output`）和 Verify（`verify`）。`schema` 仅是格式参考命令，不是第四个动作。已提交记录一致；仅在测试副本中把 crosscheck 的 `widget_beta` quantity 从 `11` 改为 `12`，会以 `SQ209` 拒绝。

## CLI 与 Python API

safe CLI 提供 local 工作流：`check` 只评估，`publish` 仅在带 `--commit` 且输出根已存在时写入，`verify` 默认检查发布物、只有提供全部原始 `--source` 时才重放。`schema` 用于查看支持的 JSON Schema。

稳定工作流入口为 `load_policy`、`load_source`、`evaluate`、`prepare_release`、`commit_release`、`verify_release`。

## 限制与许可

不包含 data acquisition、network 或 provider integration；不包含 portfolio、account 或 trading analysis；不包含 prediction 或 returns。不作 production-readiness claim，不作 adoption claim，不作 performance claim；不作 OpenAI endorsement；不作 OpenAI eligibility claim。所有示例均为 synthetic，且 not investment or financial advice。原始母项目及其 provenance 和 Git history 不属于本仓库。AI assistance 可能参与了本仓库的准备工作；任何变更在被依赖前均需要 human review。

SourceQuorum 采用 Apache-2.0 许可，详见本地 [LICENSE](LICENSE)。仓库可见性不建立 OpenAI 资格、背书、接受或支持。
