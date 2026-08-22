"""Read-only, fail-closed verification of immutable stored releases."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import cast

from .canonical import dumps_canonical, loads_strict, sha256_bytes
from .errors import ErrorCode, InputError
from .manifest import gate_report_document, policy_document
from .models import (
    ComparisonMode,
    FieldRule,
    Finding,
    GateReport,
    GateStatus,
    JsonValue,
    PreparedRelease,
    ReleasePolicy,
    ValueType,
    VerificationReport,
)
from .publish import prepare_release
from .schema import validate_document
from .source import load_source


_SMALL_MEMBER_LIMIT = 1024 * 1024
_DATA_MEMBER_LIMIT = 256 * 1024 * 1024
_FILES = {
    "manifest.json": _SMALL_MEMBER_LIMIT,
    "policy.json": _SMALL_MEMBER_LIMIT,
    "data/records.jsonl": _DATA_MEMBER_LIMIT,
    "reports/gate-report.json": _SMALL_MEMBER_LIMIT,
}
_ROOT_MEMBERS = frozenset({"manifest.json", "policy.json", "data", "reports"})
_DATA_MEMBERS = frozenset({"records.jsonl"})
_REPORT_MEMBERS = frozenset({"gate-report.json"})
_FINDING_ORDER = {code: position for position, code in enumerate(ErrorCode)}
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


class _InvalidRelease(Exception):
    def __init__(self, code: ErrorCode) -> None:
        self.code = code


def verify_release(
    release_dir: Path,
    *,
    source_dirs: Sequence[Path] = (),
) -> VerificationReport:
    """Verify one stored release without modifying its filesystem or inputs."""
    if not isinstance(release_dir, Path):
        raise ValueError("release_dir")
    raw_source_dirs = cast(object, source_dirs)
    if isinstance(raw_source_dirs, (str, bytes)) or not isinstance(source_dirs, Sequence):
        raise ValueError("source_dirs")
    source_snapshot = tuple(source_dirs)
    if not all(isinstance(directory, Path) for directory in source_snapshot):
        raise ValueError("source_dirs")
    try:
        snapshots = _snapshot_release(release_dir)
        manifest = _canonical_document(snapshots["manifest.json"], "release-manifest")
        release_id = manifest.get("release_id")
        if not isinstance(release_id, str):
            raise _InvalidRelease(ErrorCode.MANIFEST_INVALID)
        identity_document = dict(manifest)
        del identity_document["release_id"]
        if release_id != "sq-v1-" + sha256_bytes(dumps_canonical(identity_document)):
            raise _InvalidRelease(ErrorCode.RELEASE_ID_MISMATCH)
        if release_dir.name != release_id:
            raise _InvalidRelease(ErrorCode.RELEASE_ID_MISMATCH)
        _require_member_digests(manifest, snapshots)
        policy = _release_policy(snapshots["policy.json"])
        report = _gate_report(snapshots["reports/gate-report.json"])
        try:
            prepared = PreparedRelease(release_id, manifest, snapshots, report)
        except Exception:
            raise _InvalidRelease(ErrorCode.MANIFEST_INVALID) from None
        if source_snapshot:
            _replay_sources(prepared, policy, source_snapshot)
        return VerificationReport(True, release_id)
    except _InvalidRelease as error:
        return _invalid(error.code)
    except Exception:
        return _invalid(ErrorCode.MEMBER_TAMPERED)


def _invalid(*codes: ErrorCode) -> VerificationReport:
    ordered = sorted(set(codes), key=lambda code: _FINDING_ORDER[code])
    return VerificationReport(False, findings=tuple(Finding(code) for code in ordered))


def _snapshot_release(release_dir: Path) -> dict[str, bytes]:
    _require_real_directory_chain(release_dir)
    _require_exact_names(release_dir, _ROOT_MEMBERS)
    for name in ("data", "reports"):
        _require_directory(release_dir / name)
    _require_exact_names(release_dir / "data", _DATA_MEMBERS)
    _require_exact_names(release_dir / "reports", _REPORT_MEMBERS)
    return {path: _read_member(release_dir / path, limit) for path, limit in _FILES.items()}


def _require_real_directory_chain(path: Path) -> None:
    lexical = path.absolute()
    current = Path(lexical.anchor)
    try:
        for part in lexical.parts[1:]:
            current /= part
            node = os.lstat(current)
            if stat.S_ISLNK(node.st_mode):
                raise _InvalidRelease(ErrorCode.SYMLINK_FORBIDDEN)
            if not stat.S_ISDIR(node.st_mode):
                raise _InvalidRelease(ErrorCode.UNSAFE_PATH)
    except _InvalidRelease:
        raise
    except OSError:
        raise _InvalidRelease(ErrorCode.UNSAFE_PATH) from None


def _require_directory(path: Path) -> None:
    try:
        node = os.lstat(path)
    except OSError:
        raise _InvalidRelease(ErrorCode.MEMBER_MISSING) from None
    if stat.S_ISLNK(node.st_mode):
        raise _InvalidRelease(ErrorCode.SYMLINK_FORBIDDEN)
    if not stat.S_ISDIR(node.st_mode):
        raise _InvalidRelease(ErrorCode.UNSAFE_PATH)


def _require_exact_names(directory: Path, expected: frozenset[str]) -> None:
    try:
        entries = list(os.scandir(directory))
    except OSError:
        raise _InvalidRelease(ErrorCode.UNSAFE_PATH) from None
    names = {entry.name for entry in entries}
    if expected - names:
        raise _InvalidRelease(ErrorCode.MEMBER_MISSING)
    if names - expected:
        raise _InvalidRelease(ErrorCode.UNEXPECTED_MEMBER)
    for entry in entries:
        try:
            if entry.is_symlink():
                raise _InvalidRelease(ErrorCode.SYMLINK_FORBIDDEN)
        except OSError:
            raise _InvalidRelease(ErrorCode.UNSAFE_PATH) from None


def _read_member(path: Path, limit: int) -> bytes:
    try:
        expected = os.lstat(path)
    except FileNotFoundError:
        raise _InvalidRelease(ErrorCode.MEMBER_MISSING) from None
    except OSError:
        raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED) from None
    if stat.S_ISLNK(expected.st_mode):
        raise _InvalidRelease(ErrorCode.SYMLINK_FORBIDDEN)
    if not stat.S_ISREG(expected.st_mode):
        raise _InvalidRelease(ErrorCode.UNSAFE_PATH)
    if expected.st_nlink != 1 or expected.st_size > limit:
        raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
    try:
        descriptor = os.open(path, _READ_FLAGS)
        try:
            opened = os.fstat(descriptor)
            _check_open_identity(expected, opened)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
                chunks.append(chunk)
            if total != expected.st_size:
                raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
            final = os.fstat(descriptor)
            _check_open_identity(expected, final)
        finally:
            os.close(descriptor)
    except _InvalidRelease:
        raise
    except OSError:
        raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED) from None
    return b"".join(chunks)


def _check_open_identity(expected: os.stat_result, observed: os.stat_result) -> None:
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or (observed.st_dev, observed.st_ino, observed.st_size)
        != (expected.st_dev, expected.st_ino, expected.st_size)
    ):
        raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)


def _canonical_document(data: bytes, schema_name: str) -> dict[str, JsonValue]:
    try:
        document = loads_strict(data)
        if not isinstance(document, dict):
            raise ValueError
        validate_document(schema_name, document)
        if dumps_canonical(document) != data:
            raise ValueError
        return document
    except (InputError, TypeError, ValueError):
        raise _InvalidRelease(ErrorCode.MANIFEST_INVALID) from None


def _require_member_digests(
    manifest: Mapping[str, JsonValue], snapshots: Mapping[str, bytes]
) -> None:
    try:
        policy = cast(Mapping[str, object], manifest["policy"])
        gate = cast(Mapping[str, object], manifest["gate"])
        members = cast(list[Mapping[str, object]], manifest["members"])
        if policy.get("sha256") != sha256_bytes(snapshots["policy.json"]) or policy.get(
            "byte_count"
        ) != len(snapshots["policy.json"]):
            raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
        if gate.get("report_sha256") != sha256_bytes(
            snapshots["reports/gate-report.json"]
        ) or gate.get("byte_count") != len(snapshots["reports/gate-report.json"]):
            raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
        expected: dict[str, Mapping[str, object]] = {}
        for member in members:
            path = member.get("path")
            if not isinstance(path, str) or path in expected:
                raise ValueError
            expected[path] = member
        if set(expected) != {
            "policy.json",
            "data/records.jsonl",
            "reports/gate-report.json",
        }:
            raise ValueError
        for path, content in snapshots.items():
            if path == "manifest.json":
                continue
            descriptor = expected[path]
            if descriptor.get("sha256") != sha256_bytes(content) or descriptor.get(
                "byte_count"
            ) != len(content):
                raise _InvalidRelease(ErrorCode.MEMBER_TAMPERED)
    except _InvalidRelease:
        raise
    except (KeyError, TypeError, ValueError):
        raise _InvalidRelease(ErrorCode.MANIFEST_INVALID) from None


def _gate_report(data: bytes) -> GateReport:
    document = _canonical_document(data, "gate-report")
    try:
        raw_findings = document["findings"]
        if not isinstance(raw_findings, list):
            raise ValueError
        findings: list[Finding] = []
        for raw in raw_findings:
            if not isinstance(raw, Mapping):
                raise ValueError
            findings.append(
                Finding(
                    ErrorCode(cast(str, raw["code"])),
                    source_id=cast(str | None, raw.get("source_id")),
                    field=cast(str | None, raw.get("field")),
                    key_digest=cast(str | None, raw.get("key_digest")),
                    count=cast(int | None, raw.get("count")),
                )
            )
        report = GateReport(
            GateStatus(cast(str, document["status"])),
            cast(str, document["dataset_id"]),
            _utc_timestamp(document["evaluated_at"]),
            cast(int, document["source_count"]),
            cast(int, document["record_count"]),
            tuple(findings),
        )
        if gate_report_document(report) != document:
            raise ValueError
        return report
    except (KeyError, TypeError, ValueError):
        raise _InvalidRelease(ErrorCode.MANIFEST_INVALID) from None


def _utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("evaluated_at")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        raise ValueError("evaluated_at") from None


def _replay_sources(
    prepared: PreparedRelease, policy: ReleasePolicy, source_dirs: Sequence[Path]
) -> None:
    try:
        loaded = tuple(load_source(directory, policy=policy) for directory in source_dirs)
        manifest_sources = cast(list[Mapping[str, object]], prepared.manifest["sources"])
        expected_ids = {cast(str, source["source_id"]) for source in manifest_sources}
        if (
            len(loaded) != len(expected_ids)
            or {source.source_id for source in loaded} != expected_ids
        ):
            raise ValueError
        replayed = prepare_release(
            policy, loaded, evaluated_at=_utc_timestamp(prepared.manifest["evaluated_at"])
        )
        if replayed.release_id != prepared.release_id or dict(replayed.files) != dict(
            prepared.files
        ):
            raise ValueError
    except Exception:
        raise _InvalidRelease(ErrorCode.SOURCE_HASH_MISMATCH) from None


def _release_policy(data: bytes) -> ReleasePolicy:
    document = _canonical_document(data, "policy")
    try:
        limits = cast(Mapping[str, object], document["limits"])
        raw_fields = cast(list[Mapping[str, object]], document["fields"])
        fields = tuple(
            FieldRule(
                cast(str, field["name"]),
                ValueType(cast(str, field["value_type"])),
                ComparisonMode(cast(str, field["comparison"])),
                cast(bool, field["nullable"]),
                Decimal(cast(str, cast(Mapping[str, object], field["tolerances"])["absolute"])),
                Decimal(cast(str, cast(Mapping[str, object], field["tolerances"])["relative"])),
            )
            for field in raw_fields
        )
        key_fields = document["key_fields"]
        if not isinstance(key_fields, list):
            raise ValueError
        policy = ReleasePolicy(
            cast(str, document["schema_version"]),
            cast(str, document["dataset_id"]),
            tuple(cast(str, field) for field in key_fields),
            fields,
            min_sources=cast(int, limits["min_sources"]),
            max_sources=cast(int, limits["max_sources"]),
            max_age_seconds=cast(int, limits["max_age_seconds"]),
            max_future_skew_seconds=cast(int, limits["max_future_skew_seconds"]),
            max_records_per_source=cast(int, limits["max_records_per_source"]),
            max_line_bytes=cast(int, limits["max_line_bytes"]),
            max_member_bytes=cast(int, limits["max_member_bytes"]),
            require_distinct_origin_groups=cast(bool, limits["require_distinct_origin_groups"]),
        )
        if policy_document(policy) != document:
            raise ValueError
        return policy
    except (InvalidOperation, KeyError, TypeError, ValueError):
        raise _InvalidRelease(ErrorCode.MANIFEST_INVALID) from None
