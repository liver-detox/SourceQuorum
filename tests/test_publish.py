from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from dataclasses import replace
from decimal import Decimal
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any, TypeAlias, cast, overload

import pytest

from sourcequorum import (
    ComparisonMode,
    ErrorCode,
    FieldRule,
    GateRejectedError,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)
from sourcequorum.canonical import loads_strict, sha256_bytes
from sourcequorum.schema import validate_document


AT = datetime(2042, 6, 7, 8, 9, 10, 123456, tzinfo=UTC)


def policy() -> ReleasePolicy:
    return ReleasePolicy(
        "sourcequorum.policy.v1",
        "synthetic.inventory",
        ("id",),
        (
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule("name", ValueType.STRING, ComparisonMode.EXACT, True),
            FieldRule(
                "amount",
                ValueType.DECIMAL_STRING,
                ComparisonMode.NUMERIC,
                False,
                Decimal("1.2300"),
                Decimal("-0.000"),
            ),
            FieldRule("active", ValueType.BOOLEAN, ComparisonMode.EXACT, False),
        ),
    )


def batch(
    source_id: str,
    role: SourceRole,
    records: tuple[dict[str, object], ...],
    *,
    collected_at: datetime = AT,
) -> SourceBatch:
    from sourcequorum import MemberDigest

    return SourceBatch(
        source_id,
        f"origin_{source_id}",
        role,
        collected_at,
        "a" * 64 if role is SourceRole.CANDIDATE else "b" * 64,
        MemberDigest("records.jsonl", "c" * 64, 73, len(records)),
        tuple(cast("Mapping[str, Any]", MappingProxyType(record)) for record in records),
    )


def accepted_sources(
    *,
    candidate_records: tuple[dict[str, object], ...] | None = None,
    crosscheck_records: tuple[dict[str, object], ...] | None = None,
    collected_at: datetime = AT,
) -> tuple[SourceBatch, ...]:
    records = candidate_records or (
        {"id": "two", "name": "Second", "amount": "1.2300", "active": False},
        {"id": "one", "name": None, "amount": "0", "active": True},
    )
    return (
        batch("candidate", SourceRole.CANDIDATE, records, collected_at=collected_at),
        batch(
            "crosscheck",
            SourceRole.CROSSCHECK,
            crosscheck_records or records,
            collected_at=collected_at,
        ),
    )


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


def test_prepare_release_publishes_only_canonical_candidate_and_bound_documents() -> None:
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)

    assert set(release.files) == {
        "manifest.json",
        "policy.json",
        "data/records.jsonl",
        "reports/gate-report.json",
    }
    assert release.files["data/records.jsonl"].splitlines() == [
        b'{"active":true,"amount":"0","id":"one","name":null}',
        b'{"active":false,"amount":"1.2300","id":"two","name":"Second"}',
    ]
    policy_document = cast(dict[str, Any], loads_strict(release.files["policy.json"]))
    report_document = cast(dict[str, Any], loads_strict(release.files["reports/gate-report.json"]))
    manifest_document = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    validate_document("policy", policy_document)
    validate_document("gate-report", report_document)
    validate_document("release-manifest", manifest_document)
    assert policy_document["fields"][2]["tolerances"] == {"absolute": "1.23", "relative": "0"}
    assert report_document == {
        "schema_version": "sourcequorum.gate-report.v1",
        "status": "ACCEPTED",
        "dataset_id": "synthetic.inventory",
        "evaluated_at": "2042-06-07T08:09:10.123456Z",
        "source_count": 2,
        "record_count": 2,
        "findings": [],
    }
    assert manifest_document["policy"] == {
        "path": "policy.json",
        "sha256": sha256_bytes(release.files["policy.json"]),
        "byte_count": len(release.files["policy.json"]),
    }
    assert "manifest.json" not in [member["path"] for member in manifest_document["members"]]


def test_prepare_release_snapshots_the_caller_owned_source_sequence_once() -> None:
    from sourcequorum.publish import prepare_release

    first = accepted_sources(
        candidate_records=({"id": "one", "name": "First snapshot", "amount": "0", "active": True},)
    )
    later = accepted_sources(
        candidate_records=({"id": "one", "name": "Later snapshot", "amount": "0", "active": True},)
    )
    changing = _ChangingSources(first, later)

    release = prepare_release(policy(), changing, evaluated_at=AT)
    expected = prepare_release(policy(), first, evaluated_at=AT)

    assert changing.iterations == 1
    assert release.release_id == expected.release_id
    assert release.files == expected.files


def test_accepted_release_never_includes_distinctive_crosscheck_raw_value() -> None:
    from sourcequorum.publish import prepare_release

    sentinel = "999.9999"
    release = prepare_release(
        policy(),
        accepted_sources(
            candidate_records=(
                {"id": "one", "name": "same", "amount": "998.9999", "active": True},
            ),
            crosscheck_records=({"id": "one", "name": "same", "amount": sentinel, "active": True},),
        ),
        evaluated_at=AT,
    )
    assert all(sentinel.encode() not in content for content in release.files.values())
    assert sentinel not in repr(release)
    assert sentinel not in repr(release.manifest)


def test_rejected_gate_cannot_prepare_a_release_or_render_crosscheck_value() -> None:
    from sourcequorum.publish import prepare_release

    sentinel = "RAW_CROSSCHECK_SENTINEL"
    with pytest.raises(GateRejectedError) as raised:
        prepare_release(
            policy(),
            accepted_sources(
                candidate_records=(
                    {"id": "one", "name": "candidate", "amount": "0", "active": True},
                ),
                crosscheck_records=(
                    {"id": "one", "name": sentinel, "amount": "0", "active": True},
                ),
            ),
            evaluated_at=AT,
        )
    assert raised.value.code is ErrorCode.GATE_REJECTED
    assert sentinel not in repr(raised.value) + str(raised.value)


def test_release_identity_is_independent_of_source_record_and_mapping_order() -> None:
    from sourcequorum.publish import prepare_release

    first = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    reordered_records = tuple(reversed(accepted_sources()[0].records))
    reordered = (
        batch("crosscheck", SourceRole.CROSSCHECK, tuple(dict(item) for item in reordered_records)),
        batch(
            "candidate",
            SourceRole.CANDIDATE,
            tuple(dict(reversed(list(item.items()))) for item in reordered_records),
        ),
    )
    second = prepare_release(policy(), reordered, evaluated_at=AT)
    assert second.release_id == first.release_id
    assert second.files == first.files


def test_release_id_is_full_manifest_digest_without_release_id() -> None:
    from sourcequorum.publish import prepare_release
    from sourcequorum.canonical import dumps_canonical

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    manifest = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    release_id = manifest.pop("release_id")
    assert release_id == release.release_id
    assert release_id == "sq-v1-" + sha256_bytes(dumps_canonical(manifest))
    assert len(release_id) == len("sq-v1-") + 64


def test_equivalent_offsets_produce_identical_release_and_inputs_are_deeply_immutable() -> None:
    from sourcequorum.publish import prepare_release

    first = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    offset_at = AT.astimezone(timezone(timedelta(hours=-4)))
    offset_sources = tuple(
        batch(
            source.source_id,
            source.role,
            tuple(dict(record) for record in source.records),
            collected_at=source.collected_at.astimezone(timezone(timedelta(hours=9))),
        )
        for source in accepted_sources()
    )
    second = prepare_release(policy(), offset_sources, evaluated_at=offset_at)
    assert second.release_id == first.release_id
    with pytest.raises(TypeError):
        first.files["policy.json"] = b"changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        first.manifest["dataset_id"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        cast(Any, first.manifest["policy"])["path"] = "changed"


def test_release_id_changes_with_candidate_input_and_has_a_fixed_golden_value() -> None:
    from sourcequorum.publish import prepare_release

    fixture = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    changed = prepare_release(
        policy(),
        accepted_sources(
            candidate_records=(
                {"id": "two", "name": "Second", "amount": "1.2300", "active": False},
                {"id": "one", "name": "Changed", "amount": "0", "active": True},
            )
        ),
        evaluated_at=AT,
    )
    assert (
        fixture.release_id
        == "sq-v1-eb8ab9e06ab8509fab8c295aee98a9e5de24da4737294adc5770f643404b8ca3"
    )
    assert changed.release_id != fixture.release_id


def test_prepare_release_performs_no_filesystem_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    from sourcequorum.publish import prepare_release

    def forbidden(*_: object, **__: object) -> object:
        raise AssertionError("filesystem write")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    assert release.release_id.startswith("sq-v1-")


def test_prepared_release_rejects_a_gate_report_not_bound_to_its_report_member() -> None:
    from sourcequorum import GateReport, GateStatus
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    unbound_report = GateReport(
        GateStatus.ACCEPTED,
        release.gate_report.dataset_id,
        release.gate_report.evaluated_at,
        2,
        0,
    )
    with pytest.raises(ValueError, match="^gate_report$"):
        replace(release, gate_report=unbound_report)


def test_prepared_release_rejects_a_manifest_whose_release_id_is_not_recomputed() -> None:
    from sourcequorum import PreparedRelease
    from sourcequorum.canonical import dumps_canonical
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    forged_manifest = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    forged_manifest["release_id"] = "sq-v1-" + "0" * 64
    forged_files = dict(release.files)
    forged_files["manifest.json"] = dumps_canonical(forged_manifest)
    with pytest.raises(ValueError, match="^release_id$"):
        PreparedRelease(
            forged_manifest["release_id"], forged_manifest, forged_files, release.gate_report
        )


def test_prepared_release_rejects_a_member_not_bound_to_the_manifest() -> None:
    from sourcequorum import PreparedRelease
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    tampered_files = dict(release.files)
    tampered_files["data/records.jsonl"] = b"{}\n"
    with pytest.raises(ValueError, match="^manifest$"):
        PreparedRelease(release.release_id, release.manifest, tampered_files, release.gate_report)


class _SwappingFiles(Mapping[str, bytes]):
    def __init__(self, first: Mapping[str, bytes], second: Mapping[str, bytes]) -> None:
        self._first = first
        self._second = second
        self.iterations = 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        self.iterations += 1
        return iter(self._first if self.iterations == 1 else self._second)

    def __len__(self) -> int:
        return len(self._first)

    def __getitem__(self, key: str) -> bytes:
        return (self._first if self.iterations <= 1 else self._second)[key]


def test_prepared_release_snapshots_stateful_files_once_before_validation() -> None:
    from sourcequorum import PreparedRelease
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    swapped = dict(release.files)
    swapped["policy.json"] = b"{}"
    stateful = _SwappingFiles(release.files, swapped)
    copied = PreparedRelease(release.release_id, release.manifest, stateful, release.gate_report)
    assert copied.files == release.files
    assert stateful.iterations == 1


def test_prepared_release_detaches_caller_owned_manifest_and_files() -> None:
    from sourcequorum import PreparedRelease
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    manifest_input = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    files_input = dict(release.files)
    copied = PreparedRelease(release.release_id, manifest_input, files_input, release.gate_report)
    manifest_input["sources"].append({"unexpected": "changed"})
    manifest_input["policy"]["path"] = "changed"
    files_input["policy.json"] = b"changed"
    assert copied.files == release.files
    assert copied.manifest == release.manifest


def test_prepared_release_binds_policy_gate_members_and_data_counts() -> None:
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    manifest = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    policy_document = cast(dict[str, Any], loads_strict(release.files["policy.json"]))
    gate_document = cast(dict[str, Any], loads_strict(release.files["reports/gate-report.json"]))
    assert policy_document["dataset_id"] == manifest["dataset_id"]
    assert manifest["status"] == gate_document["status"] == "ACCEPTED"
    assert manifest["evaluated_at"] == gate_document["evaluated_at"]
    assert manifest["gate"] == {
        "status": "ACCEPTED",
        "report_path": "reports/gate-report.json",
        "report_sha256": sha256_bytes(release.files["reports/gate-report.json"]),
        "byte_count": len(release.files["reports/gate-report.json"]),
        "source_count": gate_document["source_count"],
        "record_count": gate_document["record_count"],
        "finding_count": len(gate_document["findings"]),
    }
    assert manifest["sources"] == [
        {
            "source_id": "candidate",
            "origin_group": "origin_candidate",
            "role": "candidate",
            "collected_at": "2042-06-07T08:09:10.123456Z",
            "source_manifest_sha256": "a" * 64,
            "records_member": {
                "path": "records.jsonl",
                "sha256": "c" * 64,
                "byte_count": 73,
                "record_count": 2,
            },
        },
        {
            "source_id": "crosscheck",
            "origin_group": "origin_crosscheck",
            "role": "crosscheck",
            "collected_at": "2042-06-07T08:09:10.123456Z",
            "source_manifest_sha256": "b" * 64,
            "records_member": {
                "path": "records.jsonl",
                "sha256": "c" * 64,
                "byte_count": 73,
                "record_count": 2,
            },
        },
    ]
    assert manifest["members"] == [
        {
            "path": "data/records.jsonl",
            "media_type": "application/jsonl",
            "byte_count": len(release.files["data/records.jsonl"]),
            "record_count": 2,
            "sha256": sha256_bytes(release.files["data/records.jsonl"]),
        },
        {
            "path": "policy.json",
            "media_type": "application/json",
            "byte_count": len(release.files["policy.json"]),
            "sha256": sha256_bytes(release.files["policy.json"]),
        },
        {
            "path": "reports/gate-report.json",
            "media_type": "application/json",
            "byte_count": len(release.files["reports/gate-report.json"]),
            "sha256": sha256_bytes(release.files["reports/gate-report.json"]),
        },
    ]
    assert release.files["data/records.jsonl"].count(b"\n") == manifest["gate"]["record_count"]


def test_prepare_release_rejects_extreme_aware_datetime_safely() -> None:
    from sourcequorum.publish import prepare_release

    extreme = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14)))
    with pytest.raises(ValueError, match="^evaluated_at$"):
        prepare_release(policy(), accepted_sources(collected_at=extreme), evaluated_at=extreme)


ManifestMutation: TypeAlias = Callable[[dict[str, Any]], None]


def _rebased_inputs(
    release: Any,
    *,
    data_bytes: bytes | None = None,
    source_count: int | None = None,
    record_count: int | None = None,
    mutate_manifest: ManifestMutation | None = None,
) -> tuple[str, dict[str, Any], dict[str, bytes], Any]:
    """Forge a schema-valid release identity so each test reaches its target guard."""
    from sourcequorum.canonical import dumps_canonical

    manifest = cast(dict[str, Any], loads_strict(release.files["manifest.json"]))
    files = dict(release.files)
    if data_bytes is not None:
        files["data/records.jsonl"] = data_bytes
    new_record_count = (
        record_count if record_count is not None else release.gate_report.record_count
    )
    new_source_count = (
        source_count if source_count is not None else release.gate_report.source_count
    )
    report = replace(
        release.gate_report, source_count=new_source_count, record_count=new_record_count
    )
    gate_document = cast(dict[str, Any], loads_strict(files["reports/gate-report.json"]))
    gate_document["source_count"] = new_source_count
    gate_document["record_count"] = new_record_count
    files["reports/gate-report.json"] = dumps_canonical(gate_document)
    manifest["gate"]["source_count"] = new_source_count
    manifest["gate"]["record_count"] = new_record_count
    for member in manifest["members"]:
        content = files[member["path"]]
        member["byte_count"] = len(content)
        member["sha256"] = sha256_bytes(content)
        if member["path"] == "data/records.jsonl":
            member["record_count"] = new_record_count
    manifest["gate"]["byte_count"] = len(files["reports/gate-report.json"])
    manifest["gate"]["report_sha256"] = sha256_bytes(files["reports/gate-report.json"])
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    manifest.pop("release_id")
    release_id = "sq-v1-" + sha256_bytes(dumps_canonical(manifest))
    manifest["release_id"] = release_id
    files["manifest.json"] = dumps_canonical(manifest)
    return release_id, manifest, files, report


def _rejects_manifest_only(
    release: Any,
    *,
    data_bytes: bytes | None = None,
    source_count: int | None = None,
    record_count: int | None = None,
    mutate_manifest: ManifestMutation | None = None,
) -> None:
    from sourcequorum import PreparedRelease

    release_id, manifest, files, report = _rebased_inputs(
        release,
        data_bytes=data_bytes,
        source_count=source_count,
        record_count=record_count,
        mutate_manifest=mutate_manifest,
    )
    with pytest.raises(ValueError, match="^manifest$") as raised:
        PreparedRelease(release_id, manifest, files, report)
    assert str(raised.value) == "manifest"
    assert "raw-manifest-sentinel" not in repr(raised.value)


def test_prepared_release_rejects_unbound_source_declarations_and_selection() -> None:
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)

    def empty_sources(manifest: dict[str, Any]) -> None:
        manifest["sources"] = []

    def duplicate_source_id(manifest: dict[str, Any]) -> None:
        manifest["sources"][1]["source_id"] = "candidate"

    def unsorted_source_id(manifest: dict[str, Any]) -> None:
        manifest["sources"] = list(reversed(manifest["sources"]))

    def duplicate_origin(manifest: dict[str, Any]) -> None:
        manifest["sources"][1]["origin_group"] = manifest["sources"][0]["origin_group"]

    def no_candidate(manifest: dict[str, Any]) -> None:
        manifest["sources"][0]["role"] = "crosscheck"

    def two_candidates(manifest: dict[str, Any]) -> None:
        manifest["sources"][1]["role"] = "candidate"

    def ghost_selection(manifest: dict[str, Any]) -> None:
        manifest["selection"]["candidate_source_id"] = "raw-manifest-sentinel"

    for mutate, source_count in (
        (empty_sources, 0),
        (duplicate_source_id, None),
        (unsorted_source_id, None),
        (duplicate_origin, None),
        (no_candidate, None),
        (two_candidates, None),
        (ghost_selection, None),
    ):
        _rejects_manifest_only(release, source_count=source_count, mutate_manifest=mutate)


def test_prepared_release_rejects_source_count_mismatch() -> None:
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    _rejects_manifest_only(release, source_count=1)


@pytest.mark.parametrize(
    ("name", "forged"),
    [
        ("blank_line", b"{}\n\n"),
        ("crlf", b"{}\r\n"),
        ("missing_final_lf", b"{}"),
        ("empty", b""),
        ("invalid_json", b"not json\n"),
        ("duplicate_keys", b'{"id":"one","id":"two"}\n'),
        ("non_object", b"[]\n"),
        ("noncanonical_order", b'{"z":0,"a":1}\n'),
    ],
)
def test_prepared_release_rejects_noncanonical_jsonl_snapshots(name: str, forged: bytes) -> None:
    from sourcequorum.publish import prepare_release

    release = prepare_release(policy(), accepted_sources(), evaluated_at=AT)
    _rejects_manifest_only(release, data_bytes=forged, record_count=forged.count(b"\n"))


class _RaisingOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        raise RuntimeError("RAW_TIMESTAMP_SENTINEL")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str | None:
        return "raising-offset"


class _StatefulOffset(tzinfo):
    """Accept the old precheck path, then expose later caller-time reuse."""

    def __init__(self, error_type: type[Exception], permitted_calls: int) -> None:
        self._calls = 0
        self._error_type = error_type
        self._permitted_calls = permitted_calls

    @property
    def calls(self) -> int:
        return self._calls

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self._calls += 1
        if self._calls > self._permitted_calls:
            raise self._error_type("RAW_TZ_SENTINEL")
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str | None:
        return "stateful-offset"


class _TimestampSentinel:
    def __repr__(self) -> str:
        return "RAW_TIMESTAMP_SENTINEL"


@pytest.mark.parametrize(
    "value",
    [
        None,
        "RAW_TIMESTAMP_SENTINEL",
        b"RAW_TIMESTAMP_SENTINEL",
        _TimestampSentinel(),
        datetime(2042, 6, 7, 8, 9, 10),
        datetime(2042, 6, 7, 8, 9, 10, tzinfo=_RaisingOffset()),
        datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14))),
    ],
)
def test_prepare_release_rejects_every_invalid_evaluated_at_without_disclosure(
    value: object,
) -> None:
    from sourcequorum.publish import prepare_release

    with pytest.raises(ValueError, match="^evaluated_at$") as raised:
        prepare_release(policy(), accepted_sources(), evaluated_at=cast(datetime, value))
    assert str(raised.value) == "evaluated_at"
    assert "RAW_TIMESTAMP_SENTINEL" not in repr(raised.value)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyError])
def test_prepare_release_detaches_stateful_evaluated_at_after_normalization(
    error_type: type[Exception],
) -> None:
    from sourcequorum.publish import prepare_release

    stateful_offset = _StatefulOffset(error_type, permitted_calls=7)
    stateful_at = datetime(2042, 6, 7, 8, 9, 10, 123456, tzinfo=stateful_offset)

    release = prepare_release(policy(), accepted_sources(), evaluated_at=stateful_at)

    assert (
        release.release_id
        == "sq-v1-eb8ab9e06ab8509fab8c295aee98a9e5de24da4737294adc5770f643404b8ca3"
    )
    assert stateful_offset.calls == 2
    assert "RAW_TZ_SENTINEL" not in repr(release) + repr(release.gate_report)
