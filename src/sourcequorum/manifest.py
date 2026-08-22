"""Pure document builders for a deterministic SourceQuorum prepared release."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast

from .models import GateReport, JsonValue, ReleasePolicy, SourceBatch


def utc_timestamp(value: datetime) -> str:
    """Format an aware instant in the one release-safe UTC representation."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def decimal_text(value: Decimal) -> str:
    """Render a finite non-negative Decimal without context-dependent notation."""
    if value.is_zero():
        return "0"
    text = format(value, "f")
    whole, separator, fractional = text.partition(".")
    whole = whole.lstrip("0") or "0"
    if not separator:
        return whole
    fractional = fractional.rstrip("0")
    return whole if not fractional else f"{whole}.{fractional}"


def policy_document(policy: ReleasePolicy) -> dict[str, JsonValue]:
    return {
        "schema_version": policy.schema_version,
        "dataset_id": policy.dataset_id,
        "key_fields": list(policy.key_fields),
        "fields": [
            {
                "name": field.name,
                "value_type": field.value_type.value,
                "comparison": field.comparison.value,
                "nullable": field.nullable,
                "tolerances": {
                    "absolute": decimal_text(field.absolute_tolerance),
                    "relative": decimal_text(field.relative_tolerance),
                },
            }
            for field in policy.fields
        ],
        "limits": {
            "min_sources": policy.min_sources,
            "max_sources": policy.max_sources,
            "max_age_seconds": policy.max_age_seconds,
            "max_future_skew_seconds": policy.max_future_skew_seconds,
            "max_records_per_source": policy.max_records_per_source,
            "max_line_bytes": policy.max_line_bytes,
            "max_member_bytes": policy.max_member_bytes,
            "require_distinct_origin_groups": policy.require_distinct_origin_groups,
        },
    }


def gate_report_document(report: GateReport) -> dict[str, JsonValue]:
    findings: list[dict[str, JsonValue]] = []
    for finding in report.findings:
        document: dict[str, JsonValue] = {"code": finding.code.value}
        for name in ("source_id", "field", "key_digest", "count"):
            value = getattr(finding, name)
            if value is not None:
                document[name] = cast(JsonValue, value)
        findings.append(document)
    return {
        "schema_version": "sourcequorum.gate-report.v1",
        "status": report.status.value,
        "dataset_id": report.dataset_id,
        "evaluated_at": utc_timestamp(report.evaluated_at),
        "source_count": report.source_count,
        "record_count": report.record_count,
        "findings": cast(JsonValue, findings),
    }


def source_summaries(sources: Sequence[SourceBatch]) -> list[dict[str, JsonValue]]:
    return [
        {
            "source_id": source.source_id,
            "origin_group": source.origin_group,
            "role": source.role.value,
            "collected_at": utc_timestamp(source.collected_at),
            "source_manifest_sha256": source.source_manifest_sha256,
            "records_member": _member_document(source.records_member),
        }
        for source in sorted(sources, key=lambda item: item.source_id)
    ]


def _member_document(member: object) -> dict[str, JsonValue]:
    path = getattr(member, "path")
    sha256 = getattr(member, "sha256")
    byte_count = getattr(member, "byte_count")
    record_count = getattr(member, "record_count")
    document: dict[str, JsonValue] = {
        "path": cast(str, path),
        "sha256": cast(str, sha256),
        "byte_count": cast(int, byte_count),
    }
    if record_count is not None:
        document["record_count"] = cast(int, record_count)
    return document


def member_descriptor(
    path: str, media_type: str, content: bytes, *, record_count: int | None = None
) -> dict[str, JsonValue]:
    from .canonical import sha256_bytes

    descriptor: dict[str, JsonValue] = {
        "path": path,
        "media_type": media_type,
        "byte_count": len(content),
        "sha256": sha256_bytes(content),
    }
    if record_count is not None:
        descriptor["record_count"] = record_count
    return descriptor


def release_manifest_document(
    *,
    release_id: str,
    policy: ReleasePolicy,
    report: GateReport,
    candidate: SourceBatch,
    sources: Sequence[SourceBatch],
    policy_bytes: bytes,
    report_bytes: bytes,
    data_bytes: bytes,
) -> dict[str, JsonValue]:
    from .canonical import sha256_bytes

    return {
        "schema_version": "sourcequorum.release-manifest.v1",
        "release_id": release_id,
        "dataset_id": policy.dataset_id,
        "status": report.status.value,
        "evaluated_at": utc_timestamp(report.evaluated_at),
        "canonicalization": {"scheme": "RFC8785", "record_framing": "JCS_BYTES_PLUS_LF"},
        "selection": {
            "mode": "EXPLICIT_CANDIDATE_NO_MERGE",
            "candidate_source_id": candidate.source_id,
        },
        "policy": {
            "path": "policy.json",
            "sha256": sha256_bytes(policy_bytes),
            "byte_count": len(policy_bytes),
        },
        "sources": cast(JsonValue, source_summaries(sources)),
        "gate": {
            "status": report.status.value,
            "report_path": "reports/gate-report.json",
            "report_sha256": sha256_bytes(report_bytes),
            "byte_count": len(report_bytes),
            "source_count": report.source_count,
            "record_count": report.record_count,
            "finding_count": len(report.findings),
        },
        "members": cast(
            JsonValue,
            sorted(
                [
                    member_descriptor(
                        "data/records.jsonl",
                        "application/jsonl",
                        data_bytes,
                        record_count=report.record_count,
                    ),
                    member_descriptor("policy.json", "application/json", policy_bytes),
                    member_descriptor("reports/gate-report.json", "application/json", report_bytes),
                ],
                key=lambda item: cast(str, item["path"]),
            ),
        ),
        "overwrite_policy": "FORBIDDEN",
    }
