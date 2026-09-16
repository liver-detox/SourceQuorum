# SourceQuorum

[English](README.md)

SourceQuorum 帮助研究人员在发布小型研究成果前，检查两个明确提供的本地来源是否一致。

首次运行时，可以直接使用仓库附带的合成示例完成一次比较、发布和验证。

## 首次使用

需要 Git 和 Python 3.11–3.14。先下载并进入仓库；如果已有本地副本，
可从仓库根目录开始，跳过下载和进入目录两步。

运行仓库附带的合成库存示例，依次完成检查、发布和已存储发布物验证。演示会创建并
自动删除临时输出。

macOS/Linux：

```bash
git clone https://github.com/liver-detox/SourceQuorum.git
cd SourceQuorum
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
python scripts/demo.py
```

Windows PowerShell：

```powershell
git clone https://github.com/liver-detox/SourceQuorum.git
cd SourceQuorum
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install .
py scripts/demo.py
```

预期输出：

```text
1/3 check: ACCEPTED
2/3 publish: COMMITTED
3/3 verify: VALID
Demo complete.
```

## 可选：逐步执行

输出根目录需要预先存在。以下命令会在 `./releases/<release-id>` 下创建发布物；
`publish` 会打印该 ID。

```bash
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

1. **检查：**输出接受或拒绝结果，不写入发布物。
2. **发布：**仅在使用 `--commit` 且输出根目录已存在时写入。
3. **验证：**检查已存储的发布物；提供全部原始来源目录时，还会重放比较。

## 帮助

```bash
sourcequorum --help
sourcequorum check --help
sourcequorum schema source
```

- candidate = 待发布来源；crosscheck = 用于交叉核对它的来源。
- `--at` 是评估时间，且必须带时区。
- 每个来源都重复一次 `--source`。
- `source.json` 中的 `source_id` 和 `origin_group` 必须以小写字母开头，
  后续只能使用小写字母、数字、`.`、`_` 或 `-`，总长不超过 128 个字符。
  例如使用 `synthetic_candidate`，不要使用大写编号。
- 修改 `records.jsonl` 后，需要同步更新 `source.json` 中的 `sha256`、
  `byte_count` 和 `record_count`；这些值对应文件的精确字节内容。

如果自建来源返回 `SQ101: invalid source manifest`，可运行
`sourcequorum schema source` 检查字段要求，尤其是上面的编号格式。

有效的不一致——即每个来源自身仍然有效，但 candidate 与 crosscheck 的值不同——会以
`SQ209` 和退出状态 1 被拒绝。

如果某一步令人困惑，请创建 GitHub Issue，并说明第一个令人困惑的步骤。

## 如何理解结果

SourceQuorum 在本地以确定性方式运行。如果提供的记录不符合所选策略，它会拒绝比较。

- **接受**表示声明的本地记录符合所选策略；这并不证明数据一定真实，也不证明
  两个来源在现实中彼此独立。
- 接受后可以创建内容寻址的发布物，SourceQuorum 不会覆盖它。验证可以发现
  已存储发布物不一致，但不能阻止拥有文件权限的人修改文件。
- 默认验证检查已存储的发布物。提供全部原始来源目录时，会使用已存储的
  `evaluated_at` 重放比较，并要求逐字节一致。两种模式都只读且离线。

## CLI 与 Python API

`schema` 用于输出支持的 JSON Schema；它是参考命令，不是第四个工作流操作。

导出的工作流入口为 `load_policy`、`load_source`、`evaluate`、`prepare_release`、
`commit_release` 和 `verify_release`。

## 适用范围

SourceQuorum 处理本地文件，且不会获取数据。仓库中的示例均为合成数据。

## 许可证

SourceQuorum 采用 Apache-2.0 许可证；详见 [LICENSE](LICENSE)。
