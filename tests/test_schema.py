from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from sourcequorum.errors import ErrorCode, InputError
from sourcequorum.schema import SCHEMA_NAMES, load_schema, schema_bytes, validate_document


SHA256 = "a" * 64
WHEN = "2035-01-02T03:04:05Z"


def _policy() -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.policy.v1",
        "dataset_id": "synthetic.inventory",
        "key_fields": ["item_id"],
        "fields": [
            {
                "name": "item_id",
                "value_type": "string",
                "comparison": "exact",
                "nullable": False,
                "tolerances": {"absolute": "0", "relative": "0"},
            },
            {
                "name": "quantity",
                "value_type": "integer",
                "comparison": "numeric",
                "nullable": False,
                "tolerances": {"absolute": "1.25", "relative": "0"},
            },
        ],
        "limits": {
            "min_sources": 2,
            "max_sources": 8,
            "max_age_seconds": 60,
            "max_future_skew_seconds": 0,
            "max_records_per_source": 10,
            "max_line_bytes": 100,
            "max_member_bytes": 1000,
            "require_distinct_origin_groups": True,
        },
    }


def _source() -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.source.v1",
        "source_id": "candidate_a",
        "origin_group": "origin_a",
        "role": "candidate",
        "collected_at": WHEN,
        "records": {
            "path": "records.jsonl",
            "sha256": SHA256,
            "byte_count": 10,
            "record_count": 1,
        },
    }


def _gate_report() -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.gate-report.v1",
        "status": "REJECTED",
        "dataset_id": "synthetic.inventory",
        "evaluated_at": WHEN,
        "source_count": 2,
        "record_count": 1,
        "findings": [{"code": "SQ209", "source_id": "crosscheck_a", "count": 1}],
    }


def _member(path: str, media_type: str, record_count: int | None = None) -> dict[str, object]:
    member: dict[str, object] = {
        "path": path,
        "media_type": media_type,
        "byte_count": 10,
        "sha256": SHA256,
    }
    if record_count is not None:
        member["record_count"] = record_count
    return member


def _records_member(record_count: int | None = None) -> dict[str, object]:
    member: dict[str, object] = {
        "path": "records.jsonl",
        "sha256": SHA256,
        "byte_count": 10,
    }
    if record_count is not None:
        member["record_count"] = record_count
    return member


def _release_manifest() -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.release-manifest.v1",
        "release_id": "sq-v1-" + SHA256,
        "dataset_id": "synthetic.inventory",
        "status": "ACCEPTED",
        "evaluated_at": WHEN,
        "canonicalization": {"scheme": "RFC8785", "record_framing": "JCS_BYTES_PLUS_LF"},
        "selection": {"mode": "EXPLICIT_CANDIDATE_NO_MERGE", "candidate_source_id": "candidate_a"},
        "policy": {"path": "policy.json", "sha256": SHA256, "byte_count": 10},
        "sources": [
            {
                "source_id": "candidate_a",
                "origin_group": "origin_a",
                "role": "candidate",
                "collected_at": WHEN,
                "source_manifest_sha256": SHA256,
                "records_member": _records_member(1),
            }
        ],
        "gate": {
            "status": "ACCEPTED",
            "report_path": "reports/gate-report.json",
            "report_sha256": SHA256,
            "byte_count": 10,
            "source_count": 2,
            "record_count": 1,
            "finding_count": 0,
        },
        "members": [
            _member("policy.json", "application/json"),
            _member("data/records.jsonl", "application/jsonl", 1),
            _member("reports/gate-report.json", "application/json"),
        ],
        "overwrite_policy": "FORBIDDEN",
    }


@pytest.mark.parametrize(
    ("name", "document"),
    [
        ("policy", _policy()),
        ("source", _source()),
        ("gate-report", _gate_report()),
        ("release-manifest", _release_manifest()),
    ],
)
def test_each_schema_accepts_its_valid_v1_document(name: str, document: dict[str, object]) -> None:
    """A schema rejecting its documented v1 shape would block all local releases."""
    validate_document(name, document)


@pytest.mark.parametrize(
    ("name", "document", "code"),
    [
        ("policy", _policy(), ErrorCode.INVALID_POLICY),
        ("source", _source(), ErrorCode.INVALID_SOURCE_MANIFEST),
        ("gate-report", _gate_report(), ErrorCode.MANIFEST_INVALID),
        ("release-manifest", _release_manifest(), ErrorCode.MANIFEST_INVALID),
    ],
)
def test_each_schema_rejects_unknown_fields_with_its_safe_error_code(
    name: str, document: dict[str, object], code: ErrorCode
) -> None:
    """Accepting undeclared members would make persisted contracts extensible by accident."""
    document["unexpected"] = True

    with pytest.raises(InputError) as raised:
        validate_document(name, document)

    assert raised.value.code is code
    assert "unexpected" not in str(raised.value)


def test_policy_enforces_exact_and_numeric_tolerance_conditions() -> None:
    """Permitting a nonzero exact tolerance would contradict exact comparison semantics."""
    invalid_exact = _policy()
    cast(list[dict[str, object]], invalid_exact["fields"])[0]["tolerances"] = {
        "absolute": "0.1",
        "relative": "0",
    }
    invalid_numeric = _policy()
    cast(list[dict[str, object]], invalid_numeric["fields"])[1]["value_type"] = "string"

    for document in (invalid_exact, invalid_numeric):
        with pytest.raises(InputError) as raised:
            validate_document("policy", document)
        assert raised.value.code is ErrorCode.INVALID_POLICY


def test_source_requires_an_rfc3339_datetime_and_exact_record_member_path() -> None:
    """A naive timestamp or arbitrary member path defeats source safety checks."""
    invalid_time = _source()
    invalid_time["collected_at"] = "2035-01-02T03:04:05"
    invalid_path = _source()
    cast(dict[str, object], invalid_path["records"])["path"] = "../records.jsonl"

    for document in (invalid_time, invalid_path):
        with pytest.raises(InputError) as raised:
            validate_document("source", document)
        assert raised.value.code is ErrorCode.INVALID_SOURCE_MANIFEST


def test_gate_report_conditionally_requires_findings_by_status() -> None:
    """An accepted report with findings or an empty rejected report would be internally false."""
    accepted = _gate_report()
    accepted["status"] = "ACCEPTED"
    rejected = _gate_report()
    rejected["findings"] = []

    for document in (accepted, rejected):
        with pytest.raises(InputError) as raised:
            validate_document("gate-report", document)
        assert raised.value.code is ErrorCode.MANIFEST_INVALID


def test_release_manifest_requires_the_frozen_accepted_shapes() -> None:
    """A mutable status or overwrite policy would undermine immutable release verification."""
    invalid_status = _release_manifest()
    invalid_status["status"] = "REJECTED"
    invalid_member_path = _release_manifest()
    cast(list[dict[str, object]], invalid_member_path["members"])[0]["path"] = "../policy.json"

    for document in (invalid_status, invalid_member_path):
        with pytest.raises(InputError) as raised:
            validate_document("release-manifest", document)
        assert raised.value.code is ErrorCode.MANIFEST_INVALID


@pytest.mark.parametrize(
    "path",
    [
        "data/",
        "data//records.jsonl",
        "data/./records.jsonl",
        "data/../records.jsonl",
        "data\\records.jsonl",
        "/data/records.jsonl",
    ],
)
def test_release_manifest_rejects_noncanonical_member_paths(path: str) -> None:
    """Unsafe components or terminal slashes would diverge from canonical member paths."""
    document = _release_manifest()
    cast(list[dict[str, object]], document["members"])[0]["path"] = path

    with pytest.raises(InputError) as raised:
        validate_document("release-manifest", document)

    assert raised.value.code is ErrorCode.MANIFEST_INVALID


def test_release_source_summary_records_member_uses_task1_digest_shape() -> None:
    """Adding media type to evidence digests would diverge from the frozen Task 1 model."""
    document = _release_manifest()
    sources = cast(list[dict[str, object]], document["sources"])
    records_member = cast(dict[str, object], sources[0]["records_member"])
    records_member["media_type"] = "application/jsonl"

    with pytest.raises(InputError) as raised:
        validate_document("release-manifest", document)

    assert raised.value.code is ErrorCode.MANIFEST_INVALID


def test_policy_requires_min_sources_not_to_exceed_max_sources() -> None:
    """A reversed source range would defer an invalid policy to later gate code."""
    document = _policy()
    limits = cast(dict[str, object], document["limits"])
    limits["min_sources"] = 8
    limits["max_sources"] = 2

    with pytest.raises(InputError) as raised:
        validate_document("policy", document)

    assert raised.value.code is ErrorCode.INVALID_POLICY


def test_schema_resources_are_raw_json_and_loads_are_independent() -> None:
    """Missing wheel data or shared mutable schemas would make validation environment-dependent."""
    assert SCHEMA_NAMES == ("policy", "source", "gate-report", "release-manifest")
    raw = schema_bytes("policy")
    first = load_schema("policy")
    second = load_schema("policy")

    assert raw.startswith(b"{")
    assert first["$schema"] == "https" + "://json-schema.org/draft/2020-12/schema"
    first["mutated"] = True
    assert "mutated" not in second


@pytest.mark.parametrize("operation", [schema_bytes, load_schema])
def test_unknown_schema_name_has_a_fixed_error(operation: Callable[[str], object]) -> None:
    """A caller typo must not select an unintended schema or disclose a local resource path."""
    with pytest.raises(ValueError, match="^schema_name$"):
        operation("unknown")


def test_unknown_schema_name_is_also_rejected_by_validation() -> None:
    """Validation must use the same closed set of document types as resource loading."""
    with pytest.raises(ValueError, match="^schema_name$"):
        validate_document("unknown", {})


def test_schema_resources_contain_no_non_schema_urls() -> None:
    """Embedded contracts must not introduce external provider or runtime dependencies."""
    for name in SCHEMA_NAMES:
        assert b"https://" in schema_bytes(name)
        assert schema_bytes(name).count(b"://") == 1
