# SourceQuorum

SourceQuorum is a local, deterministic fail-closed comparison tool for producing and checking a small research release from explicitly supplied local sources.

## Evidence boundary

This Phase A repository contains only the deliberately synthetic `synthetic.inventory.v1` example. The tested boundary accepts an explicit candidate plus an independent crosscheck when their declared local records agree. It does not obtain data, establish that declared origins are independent in the real world, prove data truth, or validate an investment conclusion.

An accepted publish creates a content-addressed release that SourceQuorum does not overwrite. This is tamper-evident, not filesystem write protection: a person with filesystem write access can still change files, but verification can detect an inconsistent stored release.

Default verification checks the stored release only. It recomputes and binds the release members, manifest, policy, report, and release ID; it does not recalculate original source bytes that were not stored with the release. Source replay requires every original source directory. Replay uses the manifest's stored `evaluated_at`, rebuilds the release from those sources, and requires the release ID and all four release members to match byte for byte. Both modes are read-only and offline.

## Five-minute Quickstart

The CLI output root must already exist. The commands below use the repository root (`.`), so a committed release is written below `./releases/<release-id>`. `release-id` is the value printed by the publish command.

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

The three user workflow actions are Evaluate (`check`), Publish (`publish --commit --output`), and Verify (`verify`). `schema` is a format-reference command, not a fourth workflow action. The checked-in records agree; changing only the crosscheck `widget_beta` quantity from `11` to `12` in a test-only copy is rejected with `SQ209`.

## CLI overview

The safe CLI offers `check` to evaluate local sources and print an accepted or rejected report without writing a release. `publish` prepares a release and writes it only with `--commit` and an existing `--output` root. `verify` performs release-internal verification by default and source replay only when every original `--source` directory is supplied. `schema` prints a supported JSON Schema for format reference.

## Python API overview

The exported workflow entry points are `load_policy`, `load_source`, `evaluate`, `prepare_release`, `commit_release`, and `verify_release`.

## Limits and non-goals

There is no data acquisition, no network, and no provider integration. There is no portfolio, no account, and no trading analysis; there is no prediction or returns. There is no production-readiness claim, no adoption claim, and no performance claim. There is no OpenAI endorsement and no OpenAI eligibility claim.

All examples are synthetic and are not investment or financial advice. The original mother project and its provenance and Git history are not part of this repository. AI assistance may have been used while preparing this repository; human review is required before relying on any change.

## License

SourceQuorum is licensed under Apache-2.0; see [LICENSE](LICENSE). Repository visibility does not establish OpenAI eligibility, endorsement, acceptance, or support.
