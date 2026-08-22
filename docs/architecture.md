# Architecture

SourceQuorum is a local, straight-line workflow with five layers:

```text
policy + local source directories
        -> strict loading and format validation
        -> candidate/crosscheck comparison
        -> accepted or rejected report
        -> explicit content-addressed publish, then verification
```

The input layer reads a fixed `policy.json` plus one candidate and at least one crosscheck source directory. The source layer validates strict JSON/JSONL, declared member digests, directory shape, paths, resource limits, and source roles. The comparison layer evaluates the policy at an explicit `evaluated_at` and fails closed on invalid input or disagreement. The publish layer creates the four-member release only for an accepted result and never overwrites an existing target. Default verification is read-only and offline: it validates the stored release without recalculating original source bytes that were not stored. Replay starts only when every original source directory is supplied, uses the manifest's `evaluated_at`, and requires the release ID plus all four release members to match byte for byte.

The CLI and Python API share this same core; neither is a separate decision engine. There are no plugins, services, databases, adapters, network acquisition, or provider integrations in this architecture.

The local filesystem is a trust boundary, not a write-protected store. The release is tamper-evident: changes can be detected by verification, but a user with filesystem write permission can still alter files.
