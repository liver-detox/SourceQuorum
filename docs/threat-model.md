# Threat model

SourceQuorum treats policies, source directories, and stored releases as untrusted local input. It fails closed on malformed JSON or JSONL, digest mismatches, schema or record errors, duplicate keys, stale inputs, source disagreement, path traversal, symlinks, hidden or unexpected members, resource-limit violations, and unsafe filesystem nodes. Public errors are intentionally limited to stable codes and safe labels rather than raw records, absolute paths, or underlying exception text.

The tool operates offline and does not fetch data, call a provider, or write during verification. Default verification checks the stored release only and does not recalculate original source bytes that were not stored. Replay is read-only, requires all original source directories, uses the manifest's `evaluated_at`, and requires the recomputed release ID and four release members to match exactly.

The local filesystem is assumed to provide the cooperative-writer boundary needed for atomic publishing and safe reads. SourceQuorum does not overwrite a release target and can detect inconsistent stored contents, but tamper-evident does not mean a person with write permission is prevented from changing files. It also does not claim protection from a malicious concurrent filesystem actor or a crash-proof distributed transaction.

Declared `origin_group` values are input assertions, not proof that sources are independent in reality. SourceQuorum does not guarantee source reality or data truthfulness, and it does not guarantee research, financial, investment, or decision validity. Human review remains required.
