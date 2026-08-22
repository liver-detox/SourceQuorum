# Manifest v1

A committed v1 release has exactly four members:

- `manifest.json`
- `policy.json`
- `data/records.jsonl`
- `reports/gate-report.json`

JSON documents use RFC 8785/JCS canonical bytes. The record member is canonical JSON per record with a single LF after each record (`JCS_BYTES_PLUS_LF`). The manifest binds policy, gate report, selected candidate data, and source-member evidence through paths, byte counts, record counts where applicable, and SHA-256 digests.

The release ID is `sq-v1-` followed by the lowercase full SHA-256 of the RFC 8785 bytes of the release manifest after removing its `release_id` field. The manifest's `overwrite_policy` is `FORBIDDEN`: SourceQuorum does not overwrite an existing target for that identity.

Default verification is release-internal. It reads the four stored members, checks canonical form, member digests, manifest binding, report and policy semantics, and the release-ID formula. It does not recalculate original source bytes that were not stored in the release.

Source replay begins only when the caller supplies every original source directory. It loads those sources at the manifest's stored `evaluated_at`, rebuilds the release, and requires both the release ID and all four release members to be byte-for-byte identical. Both verification modes are read-only and offline. Tamper-evident verification detects inconsistency; it is not filesystem write protection against someone who already has write access.

The accepted shapes are defined by the bundled versioned schemas and implementation tests; this document does not extend the format.
