# SourceQuorum

[中文说明](README.zh-CN.md)

SourceQuorum helps researchers check whether two explicitly supplied local
sources agree before publishing a small research release.

On the first run, the included synthetic example lets you check a comparison,
publish a content-addressed release, and verify it.

## Quickstart

The output root must already exist. These commands create a release under
`./releases/<release-id>`; `publish` prints the ID.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .

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

The included records agree. In a test copy, changing only the crosscheck
`widget_beta` quantity from `11` to `12` is rejected with `SQ209`.

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

SourceQuorum works with local files. It does not fetch data, connect to online
providers, brokers, or accounts, or perform trading analysis, predictions, or
return estimates. The included examples are synthetic.

## License

SourceQuorum is licensed under Apache-2.0; see [LICENSE](LICENSE).
