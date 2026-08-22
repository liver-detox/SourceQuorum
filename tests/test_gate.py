from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import asdict
from datetime import UTC, datetime, timedelta, tzinfo
from decimal import Decimal, getcontext
from types import MappingProxyType
from typing import overload

import pytest

from sourcequorum import (
    ComparisonMode,
    ErrorCode,
    FieldRule,
    GateReport,
    MemberDigest,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)
from sourcequorum.gate import evaluate


AT = datetime(2040, 1, 1, tzinfo=UTC)
KEY_ALPHA = "98bc6a0a878b279f900de96461010bbf3d27ae8dcfbc5defce86d267ddb4812e"


def policy(*, min_sources: int = 2, max_sources: int = 8, max_age: int = 60) -> ReleasePolicy:
    return ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="inventory",
        key_fields=("id",),
        fields=(
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule("name", ValueType.STRING, ComparisonMode.EXACT, True),
            FieldRule("count", ValueType.INTEGER, ComparisonMode.EXACT, False),
            FieldRule("qty", ValueType.NUMBER, ComparisonMode.NUMERIC, True, Decimal("0.1")),
            FieldRule("stamp", ValueType.DATETIME, ComparisonMode.EXACT, True),
            FieldRule("flag", ValueType.BOOLEAN, ComparisonMode.EXACT, True),
            FieldRule("amount", ValueType.DECIMAL_STRING, ComparisonMode.NUMERIC, True),
        ),
        min_sources=min_sources,
        max_sources=max_sources,
        max_age_seconds=max_age,
        max_future_skew_seconds=10,
    )


def record(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "alpha",
        "name": "part",
        "count": 1,
        "qty": 10,
        "stamp": "2040-01-01T00:00:00Z",
        "flag": True,
        "amount": "10.0",
    }
    value.update(changes)
    return value


def batch(
    source_id: str,
    role: SourceRole,
    records: tuple[object, ...] = (None,),
    *,
    origin: str | None = None,
    collected_at: datetime = AT,
) -> SourceBatch:
    actual_records = tuple(MappingProxyType(record()) if item is None else item for item in records)
    return SourceBatch(
        source_id=source_id,
        origin_group=origin or f"origin_{source_id}",
        role=role,
        collected_at=collected_at,
        source_manifest_sha256="0" * 64,
        records_member=MemberDigest("records.jsonl", "1" * 64, 1, len(actual_records)),
        records=actual_records,  # type: ignore[arg-type]
    )


def codes(report: GateReport) -> list[ErrorCode]:
    return [finding.code for finding in report.findings]


class _ChangingSources(Sequence[SourceBatch]):
    def __init__(self, first: tuple[SourceBatch, ...], later: tuple[SourceBatch, ...]) -> None:
        self._first = first
        self._later = later
        self.iterations = 0

    def __len__(self) -> int:
        return len(self._first)

    @overload
    def __getitem__(self, index: int) -> SourceBatch: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[SourceBatch]: ...

    def __getitem__(self, index: int | slice) -> SourceBatch | Sequence[SourceBatch]:
        return self._first[index]

    def __iter__(self) -> Iterator[SourceBatch]:
        current = self._first if self.iterations == 0 else self._later
        self.iterations += 1
        return iter(current)


def test_accepts_two_through_eight_and_reports_candidate_records() -> None:
    for count in range(2, 9):
        sources = (batch("candidate", SourceRole.CANDIDATE),) + tuple(
            batch(f"check_{index}", SourceRole.CROSSCHECK) for index in range(count - 1)
        )
        report = evaluate(policy(), sources, evaluated_at=AT)
        assert report.status.value == "ACCEPTED"
        assert report.source_count == count
        assert report.record_count == 1


def test_evaluate_snapshots_the_caller_owned_source_sequence_once() -> None:
    first = (
        batch("candidate", SourceRole.CANDIDATE),
        batch("check", SourceRole.CROSSCHECK),
    )
    later = (
        batch("candidate", SourceRole.CANDIDATE),
        batch("check", SourceRole.CROSSCHECK, (record(name="conflict"),)),
    )
    changing = _ChangingSources(first, later)

    report = evaluate(policy(), changing, evaluated_at=AT)

    assert changing.iterations == 1
    assert report == evaluate(policy(), first, evaluated_at=AT)


@pytest.mark.parametrize(
    ("sources", "expected"),
    [
        ((), {ErrorCode.SOURCE_COUNT_TOO_LOW, ErrorCode.CANDIDATE_COUNT_INVALID}),
        ((batch("candidate", SourceRole.CANDIDATE),), {ErrorCode.SOURCE_COUNT_TOO_LOW}),
        (
            (batch("candidate", SourceRole.CANDIDATE),)
            + tuple(batch(f"check_{i}", SourceRole.CROSSCHECK) for i in range(8)),
            {ErrorCode.RESOURCE_LIMIT_EXCEEDED},
        ),
    ],
)
def test_source_count_boundaries_reject_with_actual_count(
    sources: tuple[SourceBatch, ...], expected: set[ErrorCode]
) -> None:
    report = evaluate(policy(), sources, evaluated_at=AT)
    assert set(codes(report)) == expected
    count_findings = [finding for finding in report.findings if finding.code in expected]
    assert all(
        finding.count == len(sources) for finding in count_findings if finding.count is not None
    )


@pytest.mark.parametrize(
    "sources",
    [
        (batch("one", SourceRole.CROSSCHECK), batch("two", SourceRole.CROSSCHECK)),
        (batch("one", SourceRole.CANDIDATE), batch("two", SourceRole.CANDIDATE)),
    ],
)
def test_requires_exactly_one_candidate(sources: tuple[SourceBatch, ...]) -> None:
    report = evaluate(policy(), sources, evaluated_at=AT)
    finding = next(
        item for item in report.findings if item.code is ErrorCode.CANDIDATE_COUNT_INVALID
    )
    assert finding.count == sum(item.role is SourceRole.CANDIDATE for item in sources)


def test_duplicate_source_ids_and_origins_are_safe_and_deterministic() -> None:
    sources = (
        batch("candidate", SourceRole.CANDIDATE, origin="shared"),
        batch("same", SourceRole.CROSSCHECK, origin="shared"),
        batch("same", SourceRole.CROSSCHECK, origin="shared"),
    )
    report = evaluate(policy(), sources, evaluated_at=AT)
    assert [(item.code, item.source_id) for item in report.findings] == [
        (ErrorCode.SOURCE_ID_DUPLICATE, "same"),
        (ErrorCode.ORIGIN_NOT_INDEPENDENT, "same"),
    ]


def test_freshness_uses_aware_instants_and_accepts_exact_boundaries() -> None:
    fresh = batch("candidate", SourceRole.CANDIDATE, collected_at=AT - timedelta(seconds=60))
    future = batch("check", SourceRole.CROSSCHECK, collected_at=AT + timedelta(seconds=10))
    assert evaluate(policy(), (fresh, future), evaluated_at=AT).status.value == "ACCEPTED"
    stale = batch("candidate", SourceRole.CANDIDATE, collected_at=AT - timedelta(seconds=61))
    skewed = batch("check", SourceRole.CROSSCHECK, collected_at=AT + timedelta(seconds=11))
    report = evaluate(policy(), (stale, skewed), evaluated_at=AT)
    assert [(item.code, item.source_id) for item in report.findings] == [
        (ErrorCode.SOURCE_NOT_FRESH, "candidate"),
        (ErrorCode.SOURCE_NOT_FRESH, "check"),
    ]


@pytest.mark.parametrize(
    ("bad_record", "field"),
    [
        ({"id": "alpha"}, None),
        ({**record(), "extra": "x"}, None),
        (record(name=3), "name"),
        (record(qty=True), "qty"),
        (record(qty=float("inf")), "qty"),
        (record(qty=2**53), "qty"),
        (record(count=2**53), "count"),
        (record(amount="01"), "amount"),
        (record(amount="1e1"), "amount"),
        (record(stamp="2040-01-01T00:00:00"), "stamp"),
        (record(stamp="not-a-date"), "stamp"),
        (record(flag=1), "flag"),
        (record(id=None), "id"),
    ],
)
def test_manual_records_fail_closed_on_structure_and_type(
    bad_record: dict[str, object], field: str | None
) -> None:
    candidate = batch("candidate", SourceRole.CANDIDATE, (MappingProxyType(bad_record),))
    report = evaluate(policy(), (candidate, batch("check", SourceRole.CROSSCHECK)), evaluated_at=AT)
    finding = next(
        item for item in report.findings if item.code is ErrorCode.RECORD_SCHEMA_MISMATCH
    )
    assert finding.source_id == "candidate"
    assert finding.field == field
    assert report.status.value == "REJECTED"


def test_duplicate_composite_key_rejects_and_skips_cross_source_comparison() -> None:
    duplicate = batch(
        "candidate",
        SourceRole.CANDIDATE,
        (MappingProxyType(record()), MappingProxyType(record(name="changed"))),
    )
    report = evaluate(policy(), (duplicate, batch("check", SourceRole.CROSSCHECK)), evaluated_at=AT)
    assert [(item.code, item.source_id) for item in report.findings] == [
        (ErrorCode.DUPLICATE_RECORD_KEY, "candidate")
    ]


def test_crosscheck_key_set_mismatches_use_fixed_digest_without_raw_keys() -> None:
    candidate = batch("candidate", SourceRole.CANDIDATE)
    crosscheck = batch("check", SourceRole.CROSSCHECK, (MappingProxyType(record(id="beta")),))
    report = evaluate(policy(), (candidate, crosscheck), evaluated_at=AT)
    digests = [
        item.key_digest for item in report.findings if item.code is ErrorCode.KEY_SET_MISMATCH
    ]
    assert digests == [
        "9668fda12cbe062a58ef87916c990f9f66d3073b9ef54cc60435ea747c1cbe4e",
        KEY_ALPHA,
    ]


def test_value_comparisons_cover_exact_numeric_boundaries_and_asymmetric_null() -> None:
    candidate = batch("candidate", SourceRole.CANDIDATE)
    at_absolute_boundary = batch(
        "check_a", SourceRole.CROSSCHECK, (MappingProxyType(record(qty=10.1)),)
    )
    just_over = batch("check_b", SourceRole.CROSSCHECK, (MappingProxyType(record(qty=10.101)),))
    exact_conflict = batch(
        "check_c", SourceRole.CROSSCHECK, (MappingProxyType(record(name="other")),)
    )
    null_conflict = batch("check_d", SourceRole.CROSSCHECK, (MappingProxyType(record(name=None)),))
    report = evaluate(
        policy(),
        (candidate, at_absolute_boundary, just_over, exact_conflict, null_conflict),
        evaluated_at=AT,
    )
    conflicts = [item for item in report.findings if item.code is ErrorCode.VALUE_CONFLICT]
    assert [(item.source_id, item.field, item.key_digest) for item in conflicts] == [
        ("check_b", "qty", KEY_ALPHA),
        ("check_c", "name", KEY_ALPHA),
        ("check_d", "name", KEY_ALPHA),
    ]


def test_relative_numeric_tolerance_accepts_equality_and_rejects_just_over() -> None:
    relative_policy = ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="relative",
        key_fields=("id",),
        fields=(
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule(
                "qty", ValueType.NUMBER, ComparisonMode.NUMERIC, False, Decimal(0), Decimal("0.1")
            ),
        ),
    )
    candidate = batch(
        "candidate", SourceRole.CANDIDATE, (MappingProxyType({"id": "alpha", "qty": 9}),)
    )
    boundary = batch(
        "boundary", SourceRole.CROSSCHECK, (MappingProxyType({"id": "alpha", "qty": 10}),)
    )
    over = batch(
        "over", SourceRole.CROSSCHECK, (MappingProxyType({"id": "alpha", "qty": 10.0001}),)
    )
    report = evaluate(relative_policy, (candidate, boundary, over), evaluated_at=AT)
    assert [(item.source_id, item.field) for item in report.findings] == [("over", "qty")]


def test_exact_datetime_values_compare_as_canonical_bytes_and_decimal_negative_zero_is_valid() -> (
    None
):
    candidate = batch("candidate", SourceRole.CANDIDATE, (MappingProxyType(record(amount="-0")),))
    check = batch(
        "check",
        SourceRole.CROSSCHECK,
        (MappingProxyType(record(amount="0", stamp="2039-12-31T16:00:00-08:00")),),
    )
    report = evaluate(policy(), (candidate, check), evaluated_at=AT)
    assert [(item.code, item.source_id, item.field) for item in report.findings] == [
        (ErrorCode.VALUE_CONFLICT, "check", "stamp")
    ]


def test_key_fields_are_identity_only_and_do_not_generate_value_conflicts() -> None:
    candidate = batch("candidate", SourceRole.CANDIDATE)
    different_key = batch("check", SourceRole.CROSSCHECK, (MappingProxyType(record(id="beta")),))
    report = evaluate(policy(), (candidate, different_key), evaluated_at=AT)
    assert all(item.field != "id" for item in report.findings)


def test_findings_are_unique_and_stable_across_source_record_and_mapping_order() -> None:
    candidate = batch(
        "candidate",
        SourceRole.CANDIDATE,
        (MappingProxyType(record(id="alpha")), MappingProxyType(record(id="beta"))),
    )
    check = batch(
        "check",
        SourceRole.CROSSCHECK,
        (
            MappingProxyType(dict(reversed(list(record(id="beta").items())))),
            MappingProxyType(record(id="alpha")),
        ),
    )
    first = evaluate(policy(), (candidate, check), evaluated_at=AT)
    second = evaluate(policy(), (check, candidate), evaluated_at=AT)
    assert first == second
    assert first.findings == ()


def test_candidate_record_count_safe_findings_and_invalid_api() -> None:
    sentinel = "RAW_SENTINEL_7aa5"
    candidate = batch("candidate", SourceRole.CANDIDATE, (MappingProxyType(record(name=sentinel)),))
    crosscheck = batch("check", SourceRole.CROSSCHECK, (MappingProxyType(record(name="other")),))
    report = evaluate(policy(), (candidate, crosscheck), evaluated_at=AT)
    rendered = repr(report) + str(report) + repr(asdict(report))
    assert sentinel not in rendered
    assert report.record_count == 1
    with pytest.raises(ValueError, match="^policy$"):
        evaluate(object(), (), evaluated_at=AT)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^sources$"):
        evaluate(policy(), "not-a-source-sequence", evaluated_at=AT)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^sources$"):
        evaluate(policy(), (object(),), evaluated_at=AT)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^evaluated_at$"):
        evaluate(policy(), (), evaluated_at=datetime(2040, 1, 1))


def test_decimal_tolerance_preserves_fixed_just_over_boundary_under_low_global_precision() -> None:
    numeric_policy = ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="decimal-boundary",
        key_fields=("id",),
        fields=(
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule(
                "qty", ValueType.DECIMAL_STRING, ComparisonMode.NUMERIC, False, Decimal("0.1")
            ),
        ),
    )
    candidate = batch(
        "candidate", SourceRole.CANDIDATE, (MappingProxyType({"id": "alpha", "qty": "1"}),)
    )
    crosscheck = batch(
        "check",
        SourceRole.CROSSCHECK,
        (MappingProxyType({"id": "alpha", "qty": "1.10000000000000000000000000001"}),),
    )
    context = getcontext()
    original_precision = context.prec
    try:
        context.prec = 4
        report = evaluate(numeric_policy, (candidate, crosscheck), evaluated_at=AT)
    finally:
        context.prec = original_precision
    assert [(item.code, item.source_id, item.field) for item in report.findings] == [
        (ErrorCode.VALUE_CONFLICT, "check", "qty")
    ]


def test_decimal_tolerance_rejects_exponent_aligned_difference_over_absolute_limit() -> None:
    """Ignoring exponent alignment rounds an exact just-over-limit difference down to tolerance."""
    numeric_policy = ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="decimal-exponent-boundary",
        key_fields=("id",),
        fields=(
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule("qty", ValueType.DECIMAL_STRING, ComparisonMode.NUMERIC, False, Decimal("1")),
        ),
    )
    candidate = batch(
        "candidate", SourceRole.CANDIDATE, (MappingProxyType({"id": "alpha", "qty": "1"}),)
    )
    crosscheck = batch(
        "check",
        SourceRole.CROSSCHECK,
        (MappingProxyType({"id": "alpha", "qty": "-0.00000000000000000000000000000000000000001"}),),
    )
    context = getcontext()
    original_precision = context.prec
    try:
        context.prec = 1
        report = evaluate(numeric_policy, (candidate, crosscheck), evaluated_at=AT)
    finally:
        context.prec = original_precision
    assert [(item.code, item.source_id, item.field) for item in report.findings] == [
        (ErrorCode.VALUE_CONFLICT, "check", "qty")
    ]


@pytest.mark.parametrize(
    "crosscheck_value",
    [
        "1.00000000000000000000000000000000000000001",
        "-1.00000000000000000000000000000000000000001",
    ],
)
def test_decimal_relative_tolerance_keeps_exact_positive_and_negative_boundaries_under_hostile_context(
    crosscheck_value: str,
) -> None:
    """Global Decimal precision must not round the magnitude used for relative tolerance."""
    numeric_policy = ReleasePolicy(
        schema_version="sourcequorum.policy.v1",
        dataset_id="decimal-relative-boundary",
        key_fields=("id",),
        fields=(
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule(
                "qty",
                ValueType.DECIMAL_STRING,
                ComparisonMode.NUMERIC,
                False,
                Decimal("0"),
                Decimal("1"),
            ),
        ),
    )
    candidate = batch(
        "candidate", SourceRole.CANDIDATE, (MappingProxyType({"id": "alpha", "qty": "0"}),)
    )
    crosscheck = batch(
        "check",
        SourceRole.CROSSCHECK,
        (MappingProxyType({"id": "alpha", "qty": crosscheck_value}),),
    )
    context = getcontext()
    original_precision = context.prec
    try:
        context.prec = 1
        report = evaluate(numeric_policy, (candidate, crosscheck), evaluated_at=AT)
    finally:
        context.prec = original_precision
    assert report.status.value == "ACCEPTED"
    assert report.findings == ()


class _ExplodingZone(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta:
        raise RuntimeError("raw-tz-sentinel")

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        return "exploding"


def test_evaluated_at_utcoffset_failure_is_safe_value_error() -> None:
    with pytest.raises(ValueError, match="^evaluated_at$") as raised:
        evaluate(policy(), (), evaluated_at=datetime(2040, 1, 1, tzinfo=_ExplodingZone()))
    assert "raw-tz-sentinel" not in str(raised.value)
    assert "raw-tz-sentinel" not in repr(raised.value)


def test_policy_source_bounds_and_invalid_candidate_counts_report_zero_candidate_records() -> None:
    candidate = batch("candidate", SourceRole.CANDIDATE)
    crosscheck = batch("check", SourceRole.CROSSCHECK)
    low = evaluate(policy(min_sources=3, max_sources=3), (candidate, crosscheck), evaluated_at=AT)
    assert [(item.code, item.count) for item in low.findings] == [
        (ErrorCode.SOURCE_COUNT_TOO_LOW, 2)
    ]
    high = evaluate(
        policy(min_sources=2, max_sources=2),
        (candidate, crosscheck, batch("check_two", SourceRole.CROSSCHECK)),
        evaluated_at=AT,
    )
    assert [(item.code, item.count) for item in high.findings] == [
        (ErrorCode.RESOURCE_LIMIT_EXCEEDED, 3)
    ]
    no_candidate = evaluate(
        policy(),
        (batch("check_one", SourceRole.CROSSCHECK), batch("check_two", SourceRole.CROSSCHECK)),
        evaluated_at=AT,
    )
    two_candidates = evaluate(
        policy(),
        (candidate, batch("candidate_two", SourceRole.CANDIDATE)),
        evaluated_at=AT,
    )
    assert no_candidate.record_count == 0
    assert two_candidates.record_count == 0


@pytest.mark.parametrize(
    "sources",
    [b"", b"sources", bytearray(), bytearray(b"sources"), "", "sources"],
)
def test_bytes_and_string_like_sources_are_invalid_api_arguments(sources: object) -> None:
    with pytest.raises(ValueError, match="^sources$"):
        evaluate(policy(), sources, evaluated_at=AT)  # type: ignore[arg-type]
