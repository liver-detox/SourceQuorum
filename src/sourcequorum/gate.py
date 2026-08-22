"""Deterministic, fail-closed quorum evaluation without input disclosure."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import (
    Context,
    Decimal,
    InvalidOperation,
    MAX_EMAX,
    MIN_EMIN,
    ROUND_HALF_EVEN,
    localcontext,
)
from typing import TypeAlias, cast

from .canonical import dumps_canonical
from .errors import ErrorCode
from .models import (
    ComparisonMode,
    FieldRule,
    Finding,
    GateReport,
    GateStatus,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)

_MIN_SAFE_INTEGER = -(2**53) + 1
_MAX_SAFE_INTEGER = (2**53) - 1
_DECIMAL_STRING = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_RecordIndex: TypeAlias = dict[str, Mapping[str, object]]


def _aware(value: object) -> bool:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return False
    try:
        return value.utcoffset() is not None
    except Exception:
        return False


def _parse_datetime(value: object) -> datetime | None:
    if type(value) is not str:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if _aware(parsed) else None


def _valid_value(value: object, rule: FieldRule) -> bool:
    if value is None:
        return rule.nullable
    if rule.value_type is ValueType.STRING:
        return type(value) is str and _valid_text(value)
    if rule.value_type is ValueType.INTEGER:
        return type(value) is int and _MIN_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    if rule.value_type is ValueType.NUMBER:
        if type(value) is int:
            return _MIN_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
        return type(value) is float and math.isfinite(value)
    if rule.value_type is ValueType.DECIMAL_STRING:
        if type(value) is not str or not _DECIMAL_STRING.fullmatch(value):
            return False
        try:
            return Decimal(value).is_finite()
        except InvalidOperation:
            return False
    if rule.value_type is ValueType.BOOLEAN:
        return type(value) is bool
    if rule.value_type is ValueType.DATETIME:
        return _parse_datetime(value) is not None


def _valid_text(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _finding_sort_key(finding: Finding) -> tuple[str, str, str, str, int]:
    return (
        finding.code.value,
        finding.source_id or "",
        finding.field or "",
        finding.key_digest or "",
        finding.count if finding.count is not None else -1,
    )


def _add(findings: set[Finding], finding: Finding) -> None:
    findings.add(finding)


def _key_digest(record: Mapping[str, object], policy: ReleasePolicy) -> str | None:
    try:
        projection = {name: record[name] for name in policy.key_fields}
        return hashlib.sha256(dumps_canonical(projection)).hexdigest()
    except (KeyError, TypeError, ValueError, UnicodeError):
        return None


def _validate_records(
    source: SourceBatch, policy: ReleasePolicy, findings: set[Finding]
) -> _RecordIndex | None:
    expected_fields = frozenset(rule.name for rule in policy.fields)
    indexed: _RecordIndex = {}
    valid = True
    records = cast(tuple[object, ...], source.records)
    for raw_record in records:
        if not isinstance(raw_record, Mapping):
            _add(
                findings,
                Finding(ErrorCode.RECORD_SCHEMA_MISMATCH, source_id=source.source_id, count=1),
            )
            valid = False
            continue
        record = cast(Mapping[str, object], raw_record)
        try:
            has_expected_fields = frozenset(record.keys()) == expected_fields
        except Exception:
            has_expected_fields = False
        if not has_expected_fields:
            _add(
                findings,
                Finding(ErrorCode.RECORD_SCHEMA_MISMATCH, source_id=source.source_id, count=1),
            )
            valid = False
            continue
        record_valid = True
        for rule in policy.fields:
            try:
                value = record[rule.name]
                matches = _valid_value(value, rule)
            except Exception:
                matches = False
            if not matches:
                _add(
                    findings,
                    Finding(
                        ErrorCode.RECORD_SCHEMA_MISMATCH,
                        source_id=source.source_id,
                        field=rule.name,
                    ),
                )
                valid = False
                record_valid = False
        if not record_valid:
            continue
        digest = _key_digest(record, policy)
        if digest is None:
            _add(
                findings,
                Finding(ErrorCode.RECORD_SCHEMA_MISMATCH, source_id=source.source_id, count=1),
            )
            valid = False
            continue
        if digest in indexed:
            _add(
                findings,
                Finding(
                    ErrorCode.DUPLICATE_RECORD_KEY, source_id=source.source_id, key_digest=digest
                ),
            )
            valid = False
            continue
        indexed[digest] = record
    return indexed if valid else None


def _numeric(value: object) -> Decimal:
    if type(value) is int:
        return Decimal(value)
    if type(value) is float:
        return Decimal(str(value))
    return Decimal(cast(str, value))


def _decimal_coefficient_digits(value: Decimal) -> int:
    return len(value.as_tuple().digits)


def _decimal_exponent(value: Decimal) -> int:
    exponent = value.as_tuple().exponent
    if not isinstance(exponent, int):
        raise ValueError("decimal")
    return exponent


def _decimal_alignment_precision(*values: Decimal) -> int:
    """Return enough significant digits for exact alignment of finite decimals."""
    nonzero_values = tuple(value for value in values if not value.is_zero())
    if not nonzero_values:
        return 28
    highest_adjusted = max(value.adjusted() for value in nonzero_values)
    lowest_exponent = min(_decimal_exponent(value) for value in nonzero_values)
    return max(28, highest_adjusted - lowest_exponent + 1)


def _decimal_context(precision: int) -> Context:
    return Context(
        prec=precision,
        rounding=ROUND_HALF_EVEN,
        Emin=MIN_EMIN,
        Emax=MAX_EMAX,
    )


def _values_agree(candidate: object, crosscheck: object, rule: FieldRule) -> bool:
    if candidate is None or crosscheck is None:
        return candidate is None and crosscheck is None
    if rule.comparison is ComparisonMode.NUMERIC:
        try:
            candidate_decimal = _numeric(candidate)
            crosscheck_decimal = _numeric(crosscheck)
            magnitude = max(candidate_decimal.copy_abs(), crosscheck_decimal.copy_abs())
            product_precision = max(
                28,
                _decimal_coefficient_digits(rule.relative_tolerance)
                + _decimal_coefficient_digits(magnitude),
            )
            with localcontext(_decimal_context(product_precision)):
                relative_tolerance = rule.relative_tolerance * magnitude
            precision = _decimal_alignment_precision(
                candidate_decimal,
                crosscheck_decimal,
                rule.absolute_tolerance,
                relative_tolerance,
            )
            with localcontext(_decimal_context(precision)):
                tolerance = max(
                    rule.absolute_tolerance,
                    relative_tolerance,
                )
                return abs(candidate_decimal - crosscheck_decimal) <= tolerance
        except (InvalidOperation, TypeError, ValueError):
            return False
    try:
        return dumps_canonical(candidate) == dumps_canonical(crosscheck)
    except (TypeError, ValueError, UnicodeError):
        return False


def _governance_findings(
    policy: ReleasePolicy, sources: Sequence[SourceBatch], findings: set[Finding]
) -> bool:
    count = len(sources)
    invalid = False
    if count < policy.min_sources:
        _add(findings, Finding(ErrorCode.SOURCE_COUNT_TOO_LOW, count=count))
        invalid = True
    if count > policy.max_sources or count > 8:
        _add(findings, Finding(ErrorCode.RESOURCE_LIMIT_EXCEEDED, count=count))
        invalid = True
    candidates = [source for source in sources if source.role is SourceRole.CANDIDATE]
    if len(candidates) != 1:
        _add(findings, Finding(ErrorCode.CANDIDATE_COUNT_INVALID, count=len(candidates)))
        invalid = True
    by_id: dict[str, int] = {}
    for source in sources:
        by_id[source.source_id] = by_id.get(source.source_id, 0) + 1
    for source_id, occurrences in by_id.items():
        if occurrences > 1:
            _add(findings, Finding(ErrorCode.SOURCE_ID_DUPLICATE, source_id=source_id))
            invalid = True
    by_origin: dict[str, list[str]] = {}
    for source in sources:
        by_origin.setdefault(source.origin_group, []).append(source.source_id)
    for source_ids in by_origin.values():
        if len(source_ids) > 1:
            for source_id in sorted(source_ids)[1:]:
                _add(findings, Finding(ErrorCode.ORIGIN_NOT_INDEPENDENT, source_id=source_id))
                invalid = True
    return invalid


def _freshness_findings(
    policy: ReleasePolicy,
    sources: Sequence[SourceBatch],
    evaluated_at: datetime,
    findings: set[Finding],
) -> None:
    for source in sources:
        try:
            age = (evaluated_at - source.collected_at).total_seconds()
            future = (source.collected_at - evaluated_at).total_seconds()
            stale = age > policy.max_age_seconds
            skewed = future > policy.max_future_skew_seconds
        except Exception:
            stale = True
            skewed = False
        if stale or skewed:
            _add(findings, Finding(ErrorCode.SOURCE_NOT_FRESH, source_id=source.source_id))


def evaluate(
    policy: ReleasePolicy, sources: Sequence[SourceBatch], *, evaluated_at: datetime
) -> GateReport:
    """Evaluate an explicit candidate against independent crosschecks.

    Malformed record data is represented only by safe findings.  Programmer-facing
    argument shape errors are the sole exceptions raised by this function.
    """
    if not isinstance(policy, ReleasePolicy):
        raise ValueError("policy")
    source_input: object = sources
    if (
        isinstance(source_input, str)
        or isinstance(source_input, (bytes, bytearray))
        or not isinstance(source_input, Sequence)
    ):
        raise ValueError("sources")
    source_snapshot = tuple(cast(Sequence[object], source_input))
    if not all(isinstance(source, SourceBatch) for source in source_snapshot):
        raise ValueError("sources")
    if not _aware(evaluated_at):
        raise ValueError("evaluated_at")

    checked_sources = cast(tuple[SourceBatch, ...], source_snapshot)
    findings: set[Finding] = set()
    governance_invalid = _governance_findings(policy, checked_sources, findings)
    _freshness_findings(policy, checked_sources, evaluated_at, findings)
    indexes: dict[int, _RecordIndex | None] = {
        index: _validate_records(source, policy, findings)
        for index, source in enumerate(checked_sources)
    }
    candidates = [
        (index, source)
        for index, source in enumerate(checked_sources)
        if source.role is SourceRole.CANDIDATE
    ]
    record_count = len(candidates[0][1].records) if len(candidates) == 1 else 0

    if not governance_invalid and len(candidates) == 1:
        candidate_index, candidate = candidates[0]
        candidate_records = indexes[candidate_index]
        if candidate_records is not None:
            for index, source in sorted(
                enumerate(checked_sources), key=lambda item: item[1].source_id
            ):
                if index == candidate_index or source.role is not SourceRole.CROSSCHECK:
                    continue
                crosscheck_records = indexes[index]
                if crosscheck_records is None:
                    continue
                candidate_keys = set(candidate_records)
                crosscheck_keys = set(crosscheck_records)
                for digest in sorted(candidate_keys.symmetric_difference(crosscheck_keys)):
                    _add(
                        findings,
                        Finding(
                            ErrorCode.KEY_SET_MISMATCH,
                            source_id=source.source_id,
                            key_digest=digest,
                        ),
                    )
                for digest in sorted(candidate_keys.intersection(crosscheck_keys)):
                    candidate_record = candidate_records[digest]
                    crosscheck_record = crosscheck_records[digest]
                    for rule in policy.fields:
                        if rule.name in policy.key_fields:
                            continue
                        try:
                            agrees = _values_agree(
                                candidate_record[rule.name], crosscheck_record[rule.name], rule
                            )
                        except Exception:
                            agrees = False
                        if not agrees:
                            _add(
                                findings,
                                Finding(
                                    ErrorCode.VALUE_CONFLICT,
                                    source_id=source.source_id,
                                    field=rule.name,
                                    key_digest=digest,
                                ),
                            )

    ordered = tuple(sorted(findings, key=_finding_sort_key))
    return GateReport(
        status=GateStatus.ACCEPTED if not ordered else GateStatus.REJECTED,
        dataset_id=policy.dataset_id,
        evaluated_at=evaluated_at,
        source_count=len(checked_sources),
        record_count=record_count,
        findings=ordered,
    )
