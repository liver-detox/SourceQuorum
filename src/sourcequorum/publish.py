"""In-memory, fail-closed prepared-release construction."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import cast

from .canonical import dumps_canonical, frame_jsonl, sha256_bytes
from .errors import ErrorCode, GateRejectedError
from .gate import evaluate
from .manifest import (
    gate_report_document,
    policy_document,
    release_manifest_document,
    utc_timestamp,
)
from .models import GateStatus, JsonValue, PreparedRelease, ReleasePolicy, SourceBatch, SourceRole
from .schema import validate_document


def prepare_release(
    policy: ReleasePolicy, sources: Sequence[SourceBatch], *, evaluated_at: datetime
) -> PreparedRelease:
    """Evaluate and build exactly four immutable release members without I/O."""
    try:
        if not isinstance(evaluated_at, datetime) or evaluated_at.tzinfo is None:
            raise ValueError
        if evaluated_at.utcoffset() is None:
            raise ValueError
        normalized = evaluated_at.astimezone(UTC)
        normalized_evaluated_at = datetime(
            normalized.year,
            normalized.month,
            normalized.day,
            normalized.hour,
            normalized.minute,
            normalized.second,
            normalized.microsecond,
            tzinfo=UTC,
        )
        utc_timestamp(normalized_evaluated_at)
    except Exception:
        raise ValueError("evaluated_at") from None
    source_input: object = sources
    if isinstance(source_input, (str, bytes, bytearray)) or not isinstance(source_input, Sequence):
        raise ValueError("sources")
    source_snapshot = tuple(cast(Sequence[SourceBatch], source_input))

    report = evaluate(policy, source_snapshot, evaluated_at=normalized_evaluated_at)
    if report.status is GateStatus.REJECTED:
        raise GateRejectedError(ErrorCode.GATE_REJECTED)

    candidates = [source for source in source_snapshot if source.role is SourceRole.CANDIDATE]
    if len(candidates) != 1:
        raise GateRejectedError(ErrorCode.GATE_REJECTED)
    candidate = candidates[0]
    data_bytes = _candidate_data(policy, candidate)
    policy_bytes = dumps_canonical(policy_document(policy))
    report_bytes = dumps_canonical(gate_report_document(report))
    validate_document("policy", cast(object, policy_document(policy)))
    validate_document("gate-report", cast(object, gate_report_document(report)))

    without_id = release_manifest_document(
        release_id="sq-v1-" + "0" * 64,
        policy=policy,
        report=report,
        candidate=candidate,
        sources=source_snapshot,
        policy_bytes=policy_bytes,
        report_bytes=report_bytes,
        data_bytes=data_bytes,
    )
    del without_id["release_id"]
    release_id = "sq-v1-" + sha256_bytes(dumps_canonical(without_id))
    manifest = release_manifest_document(
        release_id=release_id,
        policy=policy,
        report=report,
        candidate=candidate,
        sources=source_snapshot,
        policy_bytes=policy_bytes,
        report_bytes=report_bytes,
        data_bytes=data_bytes,
    )
    validate_document("release-manifest", manifest)
    manifest_bytes = dumps_canonical(manifest)
    return PreparedRelease(
        release_id,
        manifest,
        {
            "manifest.json": manifest_bytes,
            "policy.json": policy_bytes,
            "data/records.jsonl": data_bytes,
            "reports/gate-report.json": report_bytes,
        },
        report,
    )


def _candidate_data(policy: ReleasePolicy, candidate: SourceBatch) -> bytes:
    ordered: list[tuple[str, JsonValue]] = []
    for record in candidate.records:
        projection = {field: record[field] for field in policy.key_fields}
        ordered.append((sha256_bytes(dumps_canonical(projection)), cast(JsonValue, dict(record))))
    return frame_jsonl(record for _, record in sorted(ordered, key=lambda item: item[0]))
