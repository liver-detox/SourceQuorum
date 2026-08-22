"""Fail-closed loading for a local policy and one local source directory."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import cast

from .canonical import dumps_canonical, loads_strict
from .errors import ErrorCode, InputError
from .models import (
    ComparisonMode,
    FieldRule,
    JsonValue,
    MemberDigest,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)
from .schema import validate_document

_MEBIBYTE = 1024 * 1024
_MEMBERS = frozenset({"source.json", "records.jsonl"})


def _input(code: ErrorCode) -> InputError:
    return InputError(code)


def _lstat(path: Path, code: ErrorCode) -> os.stat_result:
    try:
        return path.lstat()
    except OSError:
        raise _input(code) from None


def _forbid_intermediate_symlinks(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = _lstat(current, ErrorCode.UNSAFE_PATH)
        if stat.S_ISLNK(info.st_mode):
            raise _input(ErrorCode.SYMLINK_FORBIDDEN)


def _regular_file(path: Path, *, limit: int, error: ErrorCode) -> os.stat_result:
    info = _lstat(path, ErrorCode.UNSAFE_PATH)
    if stat.S_ISLNK(info.st_mode):
        raise _input(ErrorCode.SYMLINK_FORBIDDEN)
    if not stat.S_ISREG(info.st_mode):
        raise _input(ErrorCode.UNSAFE_PATH)
    if info.st_size > limit:
        raise _input(ErrorCode.RESOURCE_LIMIT_EXCEEDED)
    return info


def _read_small_file(path: Path, *, limit: int, error: ErrorCode) -> bytes:
    expected = _regular_file(path, limit=limit, error=error)
    try:
        descriptor = os.open(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                expected.st_dev,
                expected.st_ino,
            ):
                raise _input(ErrorCode.UNSAFE_PATH)
            data = stream.read(limit + 1)
    except InputError:
        raise
    except OSError:
        raise _input(error) from None
    if len(data) > limit:
        raise _input(ErrorCode.RESOURCE_LIMIT_EXCEEDED)
    return data


def _mapping(value: object, code: ErrorCode) -> Mapping[str, JsonValue]:
    if not isinstance(value, dict):
        raise _input(code)
    return cast(Mapping[str, JsonValue], value)


def _parse_collected_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("collected_at")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("collected_at")
    return parsed


def load_policy(path: Path) -> ReleasePolicy:
    """Load one schema-validated policy without exposing local input details."""
    if not isinstance(path, Path):
        raise ValueError("path")
    try:
        _forbid_intermediate_symlinks(path)
        raw = _read_small_file(path, limit=_MEBIBYTE, error=ErrorCode.INVALID_POLICY)
        document = loads_strict(raw)
        validate_document("policy", document)
        root = _mapping(document, ErrorCode.INVALID_POLICY)
        limits = _mapping(root["limits"], ErrorCode.INVALID_POLICY)
        fields = root["fields"]
        if not isinstance(fields, list):
            raise ValueError("fields")
        converted_fields: list[FieldRule] = []
        for field_value in fields:
            field = _mapping(field_value, ErrorCode.INVALID_POLICY)
            tolerances = _mapping(field["tolerances"], ErrorCode.INVALID_POLICY)
            converted_fields.append(
                FieldRule(
                    name=cast(str, field["name"]),
                    value_type=ValueType(cast(str, field["value_type"])),
                    comparison=ComparisonMode(cast(str, field["comparison"])),
                    nullable=cast(bool, field["nullable"]),
                    absolute_tolerance=Decimal(cast(str, tolerances["absolute"])),
                    relative_tolerance=Decimal(cast(str, tolerances["relative"])),
                )
            )
        key_fields = root["key_fields"]
        if not isinstance(key_fields, list):
            raise ValueError("key_fields")
        return ReleasePolicy(
            schema_version=cast(str, root["schema_version"]),
            dataset_id=cast(str, root["dataset_id"]),
            key_fields=tuple(cast(str, item) for item in key_fields),
            fields=tuple(converted_fields),
            min_sources=cast(int, limits["min_sources"]),
            max_sources=cast(int, limits["max_sources"]),
            max_age_seconds=cast(int, limits["max_age_seconds"]),
            max_future_skew_seconds=cast(int, limits["max_future_skew_seconds"]),
            max_records_per_source=cast(int, limits["max_records_per_source"]),
            max_line_bytes=cast(int, limits["max_line_bytes"]),
            max_member_bytes=cast(int, limits["max_member_bytes"]),
            require_distinct_origin_groups=cast(bool, limits["require_distinct_origin_groups"]),
        )
    except InputError as error:
        if error.code in {
            ErrorCode.UNSAFE_PATH,
            ErrorCode.SYMLINK_FORBIDDEN,
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        }:
            raise
        raise _input(ErrorCode.INVALID_POLICY) from None
    except (
        ArithmeticError,
        KeyError,
        TypeError,
        ValueError,
        InvalidOperation,
        UnicodeError,
        OSError,
    ):
        raise _input(ErrorCode.INVALID_POLICY) from None


def _source_manifest(path: Path, policy: ReleasePolicy) -> tuple[Mapping[str, JsonValue], str]:
    raw = _read_small_file(
        path, limit=min(_MEBIBYTE, policy.max_member_bytes), error=ErrorCode.INVALID_SOURCE_MANIFEST
    )
    try:
        document = loads_strict(raw)
        validate_document("source", document)
        return _mapping(document, ErrorCode.INVALID_SOURCE_MANIFEST), hashlib.sha256(
            raw
        ).hexdigest()
    except InputError as error:
        if error.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED:
            raise
        raise _input(ErrorCode.INVALID_SOURCE_MANIFEST) from None


def _load_records(
    path: Path, policy: ReleasePolicy
) -> tuple[tuple[Mapping[str, JsonValue], ...], MemberDigest]:
    expected = _regular_file(
        path, limit=policy.max_member_bytes, error=ErrorCode.SOURCE_HASH_MISMATCH
    )
    digest = hashlib.sha256()
    records: list[Mapping[str, JsonValue]] = []
    key_digests: set[str] = set()
    field_names = frozenset(rule.name for rule in policy.fields)
    try:
        descriptor = os.open(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                expected.st_dev,
                expected.st_ino,
            ):
                raise _input(ErrorCode.UNSAFE_PATH)
            byte_count = 0
            while True:
                line = stream.readline(policy.max_line_bytes + 1)
                if not line:
                    break
                if len(line) > policy.max_line_bytes:
                    raise _input(ErrorCode.RESOURCE_LIMIT_EXCEEDED)
                byte_count += len(line)
                if byte_count > policy.max_member_bytes:
                    raise _input(ErrorCode.RESOURCE_LIMIT_EXCEEDED)
                digest.update(line)
                if not line.endswith(b"\n") or b"\r" in line or line == b"\n":
                    raise _input(ErrorCode.JSONL_INVALID)
                try:
                    decoded = loads_strict(line[:-1])
                except InputError:
                    raise _input(ErrorCode.JSONL_INVALID) from None
                if not isinstance(decoded, dict):
                    raise _input(ErrorCode.JSONL_INVALID)
                record = decoded
                if frozenset(record) != field_names:
                    raise _input(ErrorCode.RECORD_SCHEMA_MISMATCH)
                try:
                    key_digest = hashlib.sha256(
                        dumps_canonical({name: record[name] for name in policy.key_fields})
                    ).hexdigest()
                except (InputError, KeyError, TypeError, ValueError):
                    raise _input(ErrorCode.RECORD_SCHEMA_MISMATCH) from None
                if key_digest in key_digests:
                    raise _input(ErrorCode.DUPLICATE_RECORD_KEY)
                key_digests.add(key_digest)
                records.append(MappingProxyType(record.copy()))
                if len(records) > policy.max_records_per_source:
                    raise _input(ErrorCode.RESOURCE_LIMIT_EXCEEDED)
            final = os.fstat(stream.fileno())
    except InputError:
        raise
    except OSError:
        raise _input(ErrorCode.UNSAFE_PATH) from None
    if not records:
        raise _input(ErrorCode.JSONL_INVALID)
    if (final.st_dev, final.st_ino, final.st_size) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
    ):
        raise _input(ErrorCode.UNSAFE_PATH)
    return tuple(records), MemberDigest(
        path="records.jsonl",
        sha256=digest.hexdigest(),
        byte_count=byte_count,
        record_count=len(records),
    )


def _exact_source_tree(directory: Path) -> tuple[Path, Path]:
    _forbid_intermediate_symlinks(directory)
    root = _lstat(directory, ErrorCode.UNSAFE_PATH)
    if stat.S_ISLNK(root.st_mode):
        raise _input(ErrorCode.SYMLINK_FORBIDDEN)
    if not stat.S_ISDIR(root.st_mode):
        raise _input(ErrorCode.UNSAFE_PATH)
    try:
        entries = list(os.scandir(directory))
    except OSError:
        raise _input(ErrorCode.UNSAFE_PATH) from None
    names = {entry.name for entry in entries}
    if names != _MEMBERS:
        raise _input(ErrorCode.UNSAFE_PATH)
    for entry in entries:
        try:
            if entry.is_symlink():
                raise _input(ErrorCode.SYMLINK_FORBIDDEN)
            if not entry.is_file(follow_symlinks=False):
                raise _input(ErrorCode.UNSAFE_PATH)
        except OSError:
            raise _input(ErrorCode.UNSAFE_PATH) from None
    return directory / "source.json", directory / "records.jsonl"


def load_source(directory: Path, *, policy: ReleasePolicy) -> SourceBatch:
    """Load the exact two-member source tree described by *policy*."""
    if not isinstance(directory, Path):
        raise ValueError("directory")
    if not isinstance(policy, ReleasePolicy):
        raise ValueError("policy")
    try:
        source_path, records_path = _exact_source_tree(directory)
    except InputError:
        raise
    except (OSError, ValueError):
        raise _input(ErrorCode.UNSAFE_PATH) from None
    manifest, source_manifest_sha256 = _source_manifest(source_path, policy)
    records, records_member = _load_records(records_path, policy)
    try:
        declared = _mapping(manifest["records"], ErrorCode.INVALID_SOURCE_MANIFEST)
        declared_member = MemberDigest(
            path=cast(str, declared["path"]),
            sha256=cast(str, declared["sha256"]),
            byte_count=cast(int, declared["byte_count"]),
            record_count=cast(int, declared["record_count"]),
        )
        if declared_member != records_member:
            raise _input(ErrorCode.SOURCE_HASH_MISMATCH)
        return SourceBatch(
            source_id=cast(str, manifest["source_id"]),
            origin_group=cast(str, manifest["origin_group"]),
            role=SourceRole(cast(str, manifest["role"])),
            collected_at=_parse_collected_at(manifest["collected_at"]),
            source_manifest_sha256=source_manifest_sha256,
            records_member=records_member,
            records=records,
        )
    except InputError:
        raise
    except (KeyError, TypeError, ValueError):
        raise _input(ErrorCode.INVALID_SOURCE_MANIFEST) from None
