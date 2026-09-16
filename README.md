# SourceQuorum

[中文说明](README.zh-CN.md)

SourceQuorum helps researchers check whether two explicitly supplied local
sources agree before publishing a small research release.

On the first run, the included synthetic example lets you check a comparison,
publish a content-addressed release, and verify it.

## First use

Requires Git and Python 3.11–3.14. Download and enter the repository first;
if you already have a checkout, start there and skip the two Git/directory steps.

Run the included synthetic inventory example from check through publish and
stored-release verification. The demo creates and removes its temporary output.

macOS/Linux:

```bash
git clone https://github.com/liver-detox/SourceQuorum.git
cd SourceQuorum
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
python scripts/demo.py
```

Windows PowerShell:

```powershell
git clone https://github.com/liver-detox/SourceQuorum.git
cd SourceQuorum
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install .
py scripts/demo.py
```

Expected output:

```text
1/3 check: ACCEPTED
2/3 publish: COMMITTED
3/3 verify: VALID
Demo complete.
```

## Optional: step by step

The output root must already exist. These commands create a release under
`./releases/<release-id>`; `publish` prints the ID.

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

1. **Check:** prints accepted or rejected without writing a release.
2. **Publish:** writes only with `--commit` and an existing output root.
3. **Verify:** checks the stored release; supplying every original source
   directory also replays the comparison.

## Help

```bash
sourcequorum --help
sourcequorum check --help
sourcequorum schema source
```

- A candidate is the source intended for release; a crosscheck is the source
  used to cross-check it.
- `--at` is the evaluation time and must include a timezone.
- Repeat `--source` once for each source.
- In `source.json`, `source_id` and `origin_group` must start with a lowercase
  letter and contain only lowercase letters, digits, `.`, `_`, or `-` (up to
  128 characters). For example, use `synthetic_candidate`, not an uppercase ID.
- After editing `records.jsonl`, update its `sha256`, `byte_count`, and
  `record_count` in `source.json`. These describe the exact file bytes.

If a custom source returns `SQ101: invalid source manifest`, inspect its
fields with `sourcequorum schema source`, including the identifier rules above.

A valid disagreement—where each source remains internally valid but the
candidate and crosscheck values differ—is rejected with `SQ209` and exit
status 1.

If a step is confusing, open a GitHub Issue and name the first confusing step.

## What the result means

SourceQuorum runs locally and deterministically. If the supplied records do not
satisfy the selected policy, it rejects the comparison.

- **Accepted** means the declared local records satisfy the selected policy;
  it does not prove that the data is true or that the sources are independent
  in the real world.
- An accepted publish creates a content-addressed release that SourceQuorum
  does not overwrite. Verification can detect an inconsistent stored release,
  but it cannot prevent someone with file access from editing it.
- Default verification checks the stored release. Supplying every original
  source directory replays the comparison using the stored `evaluated_at` and
  requires a byte-for-byte match. Both modes are read-only and offline.

## CLI and Python API

`schema` prints a supported JSON Schema; it is a reference command, not a
fourth workflow action.

The exported workflow entry points are `load_policy`, `load_source`, `evaluate`,
`prepare_release`, `commit_release`, and `verify_release`.

## Scope

SourceQuorum works with local files and does not fetch data. The included
examples are synthetic.

## License

SourceQuorum is licensed under Apache-2.0; see [LICENSE](LICENSE).
