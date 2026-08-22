from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, cast

import pytest

from sourcequorum import (
    CommitResult,
    ComparisonMode,
    ErrorCode,
    FieldRule,
    Finding,
    GateReport,
    GateStatus,
    MemberDigest,
    PreparedRelease,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
    VerificationReport,
)


def _field(name: str, value_type: ValueType = ValueType.STRING) -> FieldRule:
    return FieldRule(name, value_type, ComparisonMode.EXACT, nullable=False)


def _policy() -> ReleasePolicy:
    return ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="synthetic.inventory",
        key_fields=("item_id",),
        fields=(_field("item_id"), _field("label")),
    )


def _member() -> MemberDigest:
    return MemberDigest("records.jsonl", "a" * 64, byte_count=1, record_count=1)


def _accepted_report() -> GateReport:
    return GateReport(
        GateStatus.ACCEPTED,
        "synthetic.inventory",
        datetime(2030, 1, 1, tzinfo=timezone.utc),
        source_count=2,
        record_count=1,
    )


def test_public_enums_have_stable_wire_values() -> None:
    """Changing wire values breaks policies and reports saved by another process."""
    assert SourceRole.CANDIDATE.value == "candidate"
    assert SourceRole.CROSSCHECK.value == "crosscheck"
    assert ComparisonMode.EXACT.value == "exact"
    assert ComparisonMode.NUMERIC.value == "numeric"
    assert ValueType.DECIMAL_STRING.value == "decimal-string"
    assert GateStatus.ACCEPTED.value == "ACCEPTED"
    assert GateStatus.REJECTED.value == "REJECTED"


def test_models_are_frozen_and_slot_based() -> None:
    """Mutable or dictionary-backed policy data could change after validation."""
    policy = _policy()

    with pytest.raises(FrozenInstanceError):
        policy.dataset_id = "other"  # type: ignore[misc]
    assert not hasattr(policy, "__dict__")


def test_source_batch_deeply_snapshots_caller_owned_mapping_records() -> None:
    """Caller mutations must not change records after SourceBatch validation."""
    labels = ["first"]
    metadata = {"labels": labels}
    backing_record: dict[str, Any] = {"item_id": "alpha", "metadata": metadata}
    source = SourceBatch(
        "candidate_a",
        "origin_a",
        SourceRole.CANDIDATE,
        datetime(2030, 1, 1, tzinfo=timezone.utc),
        "a" * 64,
        _member(),
        (cast("Mapping[str, Any]", MappingProxyType(backing_record)),),
    )

    backing_record["item_id"] = "changed"
    labels.append("second")

    assert source.records[0]["item_id"] == "alpha"
    frozen_metadata = cast("Mapping[str, Any]", source.records[0]["metadata"])
    assert frozen_metadata["labels"] == ("first",)


@pytest.mark.parametrize(
    ("name", "value_type", "comparison", "absolute", "relative"),
    [
        ("bad-name", ValueType.STRING, ComparisonMode.EXACT, Decimal("0"), Decimal("0")),
        ("text", ValueType.STRING, ComparisonMode.NUMERIC, Decimal("0"), Decimal("0")),
        ("text", ValueType.STRING, ComparisonMode.EXACT, Decimal("1"), Decimal("0")),
        ("amount", ValueType.NUMBER, ComparisonMode.NUMERIC, Decimal("-1"), Decimal("0")),
    ],
)
def test_field_rule_rejects_invalid_comparison_and_tolerance_rules(
    name: str,
    value_type: ValueType,
    comparison: ComparisonMode,
    absolute: Decimal,
    relative: Decimal,
) -> None:
    """Invalid field rules could make the later quorum comparison ambiguous."""
    with pytest.raises(ValueError):
        FieldRule(name, value_type, comparison, False, absolute, relative)


@pytest.mark.parametrize(
    ("name", "value_type", "comparison", "absolute", "relative", "message"),
    [
        (
            "amount",
            ValueType.NUMBER,
            ComparisonMode.EXACT,
            Decimal("1"),
            Decimal("0"),
            "absolute_tolerance",
        ),
        (
            "amount",
            ValueType.NUMBER,
            ComparisonMode.EXACT,
            Decimal("0"),
            Decimal("1"),
            "relative_tolerance",
        ),
    ],
)
def test_field_rule_names_the_invalid_tolerance_field(
    name: str,
    value_type: ValueType,
    comparison: ComparisonMode,
    absolute: Decimal,
    relative: Decimal,
    message: str,
) -> None:
    """A combined tolerance error would not identify the field callers must repair."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        FieldRule(name, value_type, comparison, False, absolute, relative)


def test_policy_rejects_missing_key_field_and_mutable_origin_rule() -> None:
    """A policy missing declared keys or independent sources is unsafe for v0.1."""
    with pytest.raises(ValueError):
        ReleasePolicy(
            "sourcequorum.policy.v1",
            "synthetic.inventory",
            ("missing",),
            (_field("item_id"),),
        )


@pytest.mark.parametrize(
    ("min_sources", "max_sources", "message"),
    [
        (1, 8, "min_sources"),
        (3, 2, "min_sources"),
        (2, 9, "max_sources"),
    ],
)
def test_policy_names_the_invalid_source_limit(
    min_sources: int,
    max_sources: int,
    message: str,
) -> None:
    """A combined limit error would not identify the field callers must repair."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        ReleasePolicy(
            "sourcequorum.policy.v1",
            "synthetic.inventory",
            ("item_id",),
            (_field("item_id"),),
            min_sources=min_sources,
            max_sources=max_sources,
        )
    with pytest.raises(ValueError):
        ReleasePolicy(
            "sourcequorum.policy.v1",
            "synthetic.inventory",
            ("item_id",),
            (_field("item_id"),),
            require_distinct_origin_groups=False,
        )


def test_member_digest_rejects_unsafe_path_and_digest() -> None:
    """Unsafe members could escape the release tree or bypass content checks."""
    with pytest.raises(ValueError):
        MemberDigest("../records.jsonl", "a" * 64, 1)
    with pytest.raises(ValueError):
        MemberDigest("records.jsonl", "A" * 64, 1)


@pytest.mark.parametrize(
    ("constructor", "message"),
    [
        (
            lambda: FieldRule(cast(str, 123), ValueType.STRING, ComparisonMode.EXACT, False),
            "name",
        ),
        (
            lambda: ReleasePolicy(
                "sourcequorum.policy.v1",
                cast(str, 123),
                ("item_id",),
                (_field("item_id"),),
            ),
            "dataset_id",
        ),
        (lambda: MemberDigest("records.jsonl", cast(str, 123), 1), "sha256"),
        (
            lambda: SourceBatch(
                cast(str, 123),
                "origin_a",
                SourceRole.CANDIDATE,
                datetime(2030, 1, 1, tzinfo=timezone.utc),
                "a" * 64,
                _member(),
                (),
            ),
            "source_id",
        ),
        (lambda: CommitResult(cast(str, 123), Path("releases")), "release_id"),
        (lambda: VerificationReport(False, cast(str, 123)), "release_id"),
    ],
)
def test_wrong_type_identifiers_and_digests_raise_field_name_value_errors(
    constructor: Callable[[], object],
    message: str,
) -> None:
    """Wrong-type public values must fail predictably instead of leaking regex TypeErrors."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        constructor()


def test_source_batch_and_gate_report_require_aware_timestamps() -> None:
    """Naive timestamps make stale and future checks host-timezone dependent."""
    with pytest.raises(ValueError):
        SourceBatch(
            "candidate_a",
            "origin_a",
            SourceRole.CANDIDATE,
            datetime(2030, 1, 1),
            "a" * 64,
            _member(),
            (),
        )
    with pytest.raises(ValueError):
        GateReport(GateStatus.ACCEPTED, "synthetic.inventory", datetime(2030, 1, 1), 2, 1)


def test_gate_report_status_matches_findings() -> None:
    """An accepted report with findings would let invalid data be released."""
    finding = Finding(ErrorCode.VALUE_CONFLICT, source_id="crosscheck_a", count=1)
    with pytest.raises(ValueError):
        GateReport(
            GateStatus.ACCEPTED,
            "synthetic.inventory",
            datetime(2030, 1, 1, tzinfo=timezone.utc),
            2,
            1,
            (finding,),
        )
    with pytest.raises(ValueError):
        GateReport(
            GateStatus.REJECTED,
            "synthetic.inventory",
            datetime(2030, 1, 1, tzinfo=timezone.utc),
            2,
            1,
        )


def test_prepared_release_requires_an_accepted_gate_report() -> None:
    """A rejected quorum must never become a prepared release."""
    rejected = GateReport(
        GateStatus.REJECTED,
        "synthetic.inventory",
        datetime(2030, 1, 1, tzinfo=timezone.utc),
        2,
        1,
        (Finding(ErrorCode.GATE_REJECTED),),
    )
    with pytest.raises(ValueError):
        PreparedRelease("sq-v1-" + "a" * 64, {}, {}, rejected)


def test_runtime_result_and_verification_status_are_validated() -> None:
    """Invalid identities and successful reports with findings mislead callers."""
    result = CommitResult("sq-v1-" + "a" * 64, Path("releases") / ("a" * 64))
    assert result.release_id.startswith("sq-v1-")
    with pytest.raises(ValueError):
        VerificationReport(True, "sq-v1-" + "a" * 64, (Finding(ErrorCode.MEMBER_TAMPERED),))


def test_prepared_release_rejects_unbound_or_incomplete_release_contents() -> None:
    """A prepared release must carry exactly the immutable, bound release members."""
    with pytest.raises(ValueError, match="^files$"):
        PreparedRelease("sq-v1-" + "a" * 64, {}, {}, _accepted_report())
