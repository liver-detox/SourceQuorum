"""Strict immutable values shared by SourceQuorum's local APIs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import TypeAlias, cast

from .errors import ErrorCode

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SAFE_ID = re.compile(r"[a-z][a-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RELEASE_ID = re.compile(r"sq-v1-[0-9a-f]{64}\Z")
_PREPARED_RELEASE_PATHS = frozenset(
    {"manifest.json", "policy.json", "data/records.jsonl", "reports/gate-report.json"}
)


class SourceRole(str, Enum):
    CANDIDATE = "candidate"
    CROSSCHECK = "crosscheck"


class ComparisonMode(str, Enum):
    EXACT = "exact"
    NUMERIC = "numeric"


class ValueType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    DECIMAL_STRING = "decimal-string"
    BOOLEAN = "boolean"
    DATETIME = "datetime"


class GateStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _is_safe_id(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_ID.fullmatch(value))


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _is_release_id(value: object) -> bool:
    return isinstance(value, str) and bool(_RELEASE_ID.fullmatch(value))


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _is_valid_tolerance(value: Decimal) -> bool:
    return value.is_finite() and value >= 0


@dataclass(frozen=True, slots=True)
class FieldRule:
    name: str
    value_type: ValueType
    comparison: ComparisonMode
    nullable: bool
    absolute_tolerance: Decimal = Decimal(0)
    relative_tolerance: Decimal = Decimal(0)

    def __post_init__(self) -> None:
        if not _is_identifier(self.name):
            raise ValueError("name")
        if not isinstance(self.value_type, ValueType):
            raise ValueError("value_type")
        if not isinstance(self.comparison, ComparisonMode):
            raise ValueError("comparison")
        if not isinstance(self.nullable, bool):
            raise ValueError("nullable")
        if not isinstance(self.absolute_tolerance, Decimal) or not _is_valid_tolerance(
            self.absolute_tolerance
        ):
            raise ValueError("absolute_tolerance")
        if not isinstance(self.relative_tolerance, Decimal) or not _is_valid_tolerance(
            self.relative_tolerance
        ):
            raise ValueError("relative_tolerance")
        if self.comparison is ComparisonMode.NUMERIC and self.value_type not in {
            ValueType.INTEGER,
            ValueType.NUMBER,
            ValueType.DECIMAL_STRING,
        }:
            raise ValueError("comparison")
        if self.comparison is ComparisonMode.EXACT and self.absolute_tolerance != 0:
            raise ValueError("absolute_tolerance")
        if self.comparison is ComparisonMode.EXACT and self.relative_tolerance != 0:
            raise ValueError("relative_tolerance")


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    schema_version: str
    dataset_id: str
    key_fields: tuple[str, ...]
    fields: tuple[FieldRule, ...]
    min_sources: int = 2
    require_distinct_origin_groups: bool = True
    max_age_seconds: int = 86400
    max_future_skew_seconds: int = 300
    max_sources: int = 8
    max_records_per_source: int = 100000
    max_line_bytes: int = 1048576
    max_member_bytes: int = 268435456

    def __post_init__(self) -> None:
        if self.schema_version != "sourcequorum.policy.v1":
            raise ValueError("schema_version")
        if not _is_safe_id(self.dataset_id):
            raise ValueError("dataset_id")
        if not isinstance(self.key_fields, tuple) or not self.key_fields:
            raise ValueError("key_fields")
        if not all(isinstance(field, str) and _is_identifier(field) for field in self.key_fields):
            raise ValueError("key_fields")
        if len(set(self.key_fields)) != len(self.key_fields):
            raise ValueError("key_fields")
        if not isinstance(self.fields, tuple) or not self.fields:
            raise ValueError("fields")
        if not all(isinstance(field, FieldRule) for field in self.fields):
            raise ValueError("fields")
        field_names = tuple(field.name for field in self.fields)
        if len(set(field_names)) != len(field_names):
            raise ValueError("fields")
        if not set(self.key_fields).issubset(field_names):
            raise ValueError("key_fields")
        if (
            not isinstance(self.require_distinct_origin_groups, bool)
            or not self.require_distinct_origin_groups
        ):
            raise ValueError("require_distinct_origin_groups")
        if isinstance(self.min_sources, bool) or not isinstance(self.min_sources, int):
            raise ValueError("min_sources")
        if self.min_sources < 2:
            raise ValueError("min_sources")
        if isinstance(self.max_sources, bool) or not isinstance(self.max_sources, int):
            raise ValueError("max_sources")
        if self.max_sources > 8:
            raise ValueError("max_sources")
        if self.min_sources > self.max_sources:
            raise ValueError("min_sources")
        if (
            isinstance(self.max_future_skew_seconds, bool)
            or not isinstance(self.max_future_skew_seconds, int)
            or self.max_future_skew_seconds < 0
        ):
            raise ValueError("max_future_skew_seconds")
        for field_name, value in (
            ("max_age_seconds", self.max_age_seconds),
            ("max_records_per_source", self.max_records_per_source),
            ("max_line_bytes", self.max_line_bytes),
            ("max_member_bytes", self.max_member_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(field_name)


def _is_canonical_member_path(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


@dataclass(frozen=True, slots=True)
class MemberDigest:
    path: str
    sha256: str
    byte_count: int
    record_count: int | None = None

    def __post_init__(self) -> None:
        if not _is_canonical_member_path(self.path):
            raise ValueError("path")
        if not _is_sha256(self.sha256):
            raise ValueError("sha256")
        if (
            isinstance(self.byte_count, bool)
            or not isinstance(self.byte_count, int)
            or self.byte_count < 0
        ):
            raise ValueError("byte_count")
        if self.record_count is not None and (
            isinstance(self.record_count, bool)
            or not isinstance(self.record_count, int)
            or self.record_count < 0
        ):
            raise ValueError("record_count")


@dataclass(frozen=True, slots=True)
class SourceBatch:
    source_id: str
    origin_group: str
    role: SourceRole
    collected_at: datetime
    source_manifest_sha256: str
    records_member: MemberDigest
    records: tuple[Mapping[str, JsonValue], ...]

    def __post_init__(self) -> None:
        if not _is_safe_id(self.source_id):
            raise ValueError("source_id")
        if not _is_safe_id(self.origin_group):
            raise ValueError("origin_group")
        if not isinstance(self.role, SourceRole):
            raise ValueError("role")
        if not isinstance(self.collected_at, datetime) or not _is_aware(self.collected_at):
            raise ValueError("collected_at")
        if not _is_sha256(self.source_manifest_sha256):
            raise ValueError("source_manifest_sha256")
        if not isinstance(self.records_member, MemberDigest):
            raise ValueError("records_member")
        if not isinstance(self.records, tuple):
            raise ValueError("records")
        object.__setattr__(
            self,
            "records",
            tuple(
                cast(Mapping[str, JsonValue], _freeze_json(cast(JsonValue, record)))
                if isinstance(record, Mapping)
                else record
                for record in self.records
            ),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    code: ErrorCode
    source_id: str | None = None
    field: str | None = None
    key_digest: str | None = None
    count: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, ErrorCode):
            raise ValueError("code")
        if self.source_id is not None and not _is_safe_id(self.source_id):
            raise ValueError("source_id")
        if self.field is not None and not _is_identifier(self.field):
            raise ValueError("field")
        if self.key_digest is not None and not _is_sha256(self.key_digest):
            raise ValueError("key_digest")
        if self.count is not None and (
            isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 0
        ):
            raise ValueError("count")


@dataclass(frozen=True, slots=True)
class GateReport:
    status: GateStatus
    dataset_id: str
    evaluated_at: datetime
    source_count: int
    record_count: int
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, GateStatus):
            raise ValueError("status")
        if not _is_safe_id(self.dataset_id):
            raise ValueError("dataset_id")
        if not isinstance(self.evaluated_at, datetime) or not _is_aware(self.evaluated_at):
            raise ValueError("evaluated_at")
        for field_name, value in (
            ("source_count", self.source_count),
            ("record_count", self.record_count),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(field_name)
        if not isinstance(self.findings, tuple) or not all(
            isinstance(finding, Finding) for finding in self.findings
        ):
            raise ValueError("findings")
        if self.status is GateStatus.ACCEPTED and self.findings:
            raise ValueError("findings")
        if self.status is GateStatus.REJECTED and not self.findings:
            raise ValueError("findings")


@dataclass(frozen=True, slots=True)
class PreparedRelease:
    release_id: str
    manifest: Mapping[str, JsonValue]
    files: Mapping[str, bytes]
    gate_report: GateReport

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, Mapping):
            raise ValueError("manifest")
        if not isinstance(self.files, Mapping):
            raise ValueError("files")
        try:
            manifest_snapshot = _thaw_json(self.manifest)
            files_snapshot = _snapshot_files(self.files)
        except Exception:
            raise ValueError("manifest") from None
        if not _is_release_id(self.release_id):
            raise ValueError("release_id")
        if not isinstance(self.gate_report, GateReport):
            raise ValueError("gate_report")
        if self.gate_report.status is not GateStatus.ACCEPTED:
            raise ValueError("gate_report")
        if frozenset(files_snapshot) != _PREPARED_RELEASE_PATHS or not all(
            isinstance(path, str) and type(content) is bytes
            for path, content in files_snapshot.items()
        ):
            raise ValueError("files")
        try:
            from .canonical import dumps_canonical, loads_strict, sha256_bytes
            from .schema import validate_document

            encoded_manifest = files_snapshot["manifest.json"]
            parsed_manifest = loads_strict(encoded_manifest)
            if not isinstance(parsed_manifest, dict):
                raise ValueError
            validate_document("release-manifest", parsed_manifest)
            if (
                manifest_snapshot != parsed_manifest
                or dumps_canonical(parsed_manifest) != encoded_manifest
            ):
                raise ValueError
        except Exception:
            raise ValueError("manifest") from None
        try:
            if parsed_manifest.get("release_id") != self.release_id:
                raise ValueError
            identity_document = dict(parsed_manifest)
            del identity_document["release_id"]
            if self.release_id != "sq-v1-" + sha256_bytes(dumps_canonical(identity_document)):
                raise ValueError
        except Exception:
            raise ValueError("release_id") from None
        try:
            member_documents = parsed_manifest["members"]
            if not isinstance(member_documents, list) or len(member_documents) != 3:
                raise ValueError
            declared_members: dict[str, Mapping[str, object]] = {}
            for member in member_documents:
                if not isinstance(member, Mapping):
                    raise ValueError
                path = member.get("path")
                if not isinstance(path, str) or path in declared_members:
                    raise ValueError
                declared_members[path] = member
            data_bytes = files_snapshot["data/records.jsonl"]
            data_record_count = _canonical_jsonl_record_count(data_bytes)
            expected_members = [
                {
                    "path": "data/records.jsonl",
                    "media_type": "application/jsonl",
                    "byte_count": len(data_bytes),
                    "record_count": data_record_count,
                    "sha256": sha256_bytes(data_bytes),
                },
                {
                    "path": "policy.json",
                    "media_type": "application/json",
                    "byte_count": len(files_snapshot["policy.json"]),
                    "sha256": sha256_bytes(files_snapshot["policy.json"]),
                },
                {
                    "path": "reports/gate-report.json",
                    "media_type": "application/json",
                    "byte_count": len(files_snapshot["reports/gate-report.json"]),
                    "sha256": sha256_bytes(files_snapshot["reports/gate-report.json"]),
                },
            ]
            if member_documents != expected_members:
                raise ValueError
            policy_descriptor = parsed_manifest["policy"]
            gate_descriptor = parsed_manifest["gate"]
            if not isinstance(policy_descriptor, Mapping) or not isinstance(
                gate_descriptor, Mapping
            ):
                raise ValueError
            policy_document = loads_strict(files_snapshot["policy.json"])
            if not isinstance(policy_document, dict):
                raise ValueError
            validate_document("policy", policy_document)
            if dumps_canonical(policy_document) != files_snapshot["policy.json"]:
                raise ValueError
            if policy_document.get("dataset_id") != parsed_manifest.get("dataset_id"):
                raise ValueError
            gate_document = loads_strict(files_snapshot["reports/gate-report.json"])
            if not isinstance(gate_document, dict):
                raise ValueError
            validate_document("gate-report", gate_document)
            if dumps_canonical(gate_document) != files_snapshot["reports/gate-report.json"]:
                raise ValueError
            gate_findings = gate_document.get("findings")
            if not isinstance(gate_findings, list):
                raise ValueError
            _validate_source_declarations(parsed_manifest, gate_document)
            if (
                parsed_manifest.get("dataset_id") != gate_document.get("dataset_id")
                or parsed_manifest.get("status") != gate_document.get("status")
                or parsed_manifest.get("evaluated_at") != gate_document.get("evaluated_at")
                or gate_descriptor.get("status") != gate_document.get("status")
                or gate_descriptor.get("source_count") != gate_document.get("source_count")
                or gate_descriptor.get("record_count") != gate_document.get("record_count")
                or gate_descriptor.get("finding_count") != len(gate_findings)
                or gate_document.get("record_count") != data_record_count
            ):
                raise ValueError
            if (
                policy_descriptor.get("path") != "policy.json"
                or policy_descriptor.get("sha256") != sha256_bytes(files_snapshot["policy.json"])
                or policy_descriptor.get("byte_count") != len(files_snapshot["policy.json"])
                or gate_descriptor.get("report_path") != "reports/gate-report.json"
                or gate_descriptor.get("report_sha256")
                != sha256_bytes(files_snapshot["reports/gate-report.json"])
                or gate_descriptor.get("byte_count")
                != len(files_snapshot["reports/gate-report.json"])
            ):
                raise ValueError
        except Exception:
            raise ValueError("manifest") from None
        try:
            from .manifest import gate_report_document

            if gate_document != gate_report_document(self.gate_report):
                raise ValueError
        except Exception:
            raise ValueError("gate_report") from None
        object.__setattr__(self, "manifest", _freeze_json(cast(JsonValue, parsed_manifest)))
        object.__setattr__(
            self,
            "files",
            MappingProxyType({path: bytes(content) for path, content in files_snapshot.items()}),
        )


def _freeze_json(value: JsonValue) -> JsonValue:
    """Recursively detach release metadata from caller-owned JSON containers."""
    if isinstance(value, Mapping):
        return cast(
            JsonValue, MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
        )
    if isinstance(value, list):
        return cast(JsonValue, tuple(_freeze_json(item) for item in value))
    return value


def _thaw_json(value: object) -> JsonValue:
    """Return a plain JSON container solely for constructor equality checks."""
    if isinstance(value, Mapping):
        copied: dict[str, JsonValue] = {}
        for key in value:
            if not isinstance(key, str) or key in copied:
                raise ValueError("manifest")
            copied[key] = _thaw_json(value[key])
        return cast(JsonValue, copied)
    if isinstance(value, (list, tuple)):
        return cast(JsonValue, [_thaw_json(item) for item in value])
    return cast(JsonValue, value)


def _snapshot_files(value: Mapping[str, bytes]) -> dict[str, bytes]:
    """Copy an arbitrary Mapping with one controlled key iteration."""
    copied: dict[str, bytes] = {}
    for path in value:
        if not isinstance(path, str) or path in copied:
            raise ValueError("files")
        copied[path] = value[path]
    return copied


def _canonical_jsonl_record_count(data: bytes) -> int:
    """Validate the declared JCS-bytes-plus-LF data-member contract."""
    if not data or b"\r" in data or not data.endswith(b"\n"):
        raise ValueError("manifest")
    raw_lines = data[:-1].split(b"\n")
    if not raw_lines or any(not line for line in raw_lines):
        raise ValueError("manifest")
    from .canonical import dumps_canonical, loads_strict

    for raw_line in raw_lines:
        record = loads_strict(raw_line)
        if not isinstance(record, dict) or dumps_canonical(record) != raw_line:
            raise ValueError("manifest")
    return len(raw_lines)


def _validate_source_declarations(
    manifest: Mapping[str, object], gate_document: Mapping[str, object]
) -> None:
    """Bind source summaries and the explicit candidate selection to the gate."""
    sources = manifest.get("sources")
    gate = manifest.get("gate")
    selection = manifest.get("selection")
    if (
        not isinstance(sources, list)
        or not sources
        or not isinstance(gate, Mapping)
        or not isinstance(selection, Mapping)
        or len(sources) != gate_document.get("source_count")
        or len(sources) != gate.get("source_count")
    ):
        raise ValueError("manifest")
    source_ids: list[str] = []
    origins: set[str] = set()
    candidate_ids: list[str] = []
    for source in sources:
        if not isinstance(source, Mapping):
            raise ValueError("manifest")
        source_id = source.get("source_id")
        origin_group = source.get("origin_group")
        role = source.get("role")
        if not isinstance(source_id, str) or not isinstance(origin_group, str):
            raise ValueError("manifest")
        if source_id in source_ids or origin_group in origins:
            raise ValueError("manifest")
        source_ids.append(source_id)
        origins.add(origin_group)
        if role == SourceRole.CANDIDATE.value:
            candidate_ids.append(source_id)
    if source_ids != sorted(source_ids) or len(candidate_ids) != 1:
        raise ValueError("manifest")
    if selection.get("candidate_source_id") != candidate_ids[0]:
        raise ValueError("manifest")


@dataclass(frozen=True, slots=True)
class CommitResult:
    release_id: str
    release_directory: Path

    def __post_init__(self) -> None:
        if not _is_release_id(self.release_id):
            raise ValueError("release_id")
        if not isinstance(self.release_directory, Path):
            raise ValueError("release_directory")


@dataclass(frozen=True, slots=True)
class VerificationReport:
    valid: bool
    release_id: str | None = None
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.valid, bool):
            raise ValueError("valid")
        if self.release_id is not None and not _is_release_id(self.release_id):
            raise ValueError("release_id")
        if not isinstance(self.findings, tuple) or not all(
            isinstance(finding, Finding) for finding in self.findings
        ):
            raise ValueError("findings")
        if self.valid and self.findings:
            raise ValueError("findings")
