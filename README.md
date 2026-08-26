# SourceQuorum

SourceQuorum helps researchers check whether two explicitly supplied local
sources agree before publishing a small research release.

**On the first run:** get an accepted or rejected comparison, then create
and verify a content-addressed release from the included synthetic example.

## Quickstart

The output root must already exist. These commands write a committed release
under `./releases/<release-id>`; the publish command prints the ID.

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

The checked-in records agree. In a test-only copy, changing only the crosscheck `widget_beta` quantity from `11` to `12` is rejected with `SQ209`.

## What the result means

SourceQuorum is a local, deterministic fail-closed comparison. The tested
boundary accepts an explicit candidate plus an independent crosscheck.

- **Accepted** means the declared local records satisfy the selected policy;
  it does not prove the data true or the sources independent in the real world.
- An accepted publish creates a content-addressed release that SourceQuorum does not overwrite. It is tamper-evident, not filesystem write protection:
  someone with write access can change files, while verification can detect
  an inconsistent stored release.
- Default verification checks the stored release only. It binds the release
  members, manifest, policy, report, and release ID; it does not recalculate
  unstored source bytes. Replay requires every original source directory,
  uses the stored `evaluated_at`, and requires the ID and all four members to
  match byte for byte. Both modes are read-only and offline.

## CLI and Python API

`schema` prints a supported JSON Schema; it is a reference command, not a
fourth workflow action.

The exported workflow entry points are `load_policy`, `load_source`, `evaluate`, `prepare_release`, `commit_release`, and `verify_release`.

## Scope and limits

The safe CLI has no data acquisition, no network, no provider integration, no portfolio, no account, no trading analysis, and no prediction or returns. It
makes no production-readiness claim, no adoption claim, no performance claim,
no OpenAI endorsement, and no OpenAI eligibility claim. All included public
examples are synthetic and not investment or financial advice; use only
material you are permitted to handle.

The original mother project and its provenance and Git history are not part of this repository. AI assistance may have been used; human review remains
required. Repository visibility does not establish OpenAI eligibility, endorsement, acceptance, or support.

## License

SourceQuorum is licensed under Apache-2.0; see [LICENSE](LICENSE).
