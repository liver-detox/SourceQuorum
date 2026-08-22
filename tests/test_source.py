"""Contract tests for the fail-closed local source loader."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sourcequorum import ErrorCode, InputError, ReleasePolicy, SourceBatch, load_policy, load_source


def _policy_document(**limits: object) -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.policy.v1",
        "dataset_id": "synthetic.inventory.v1",
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
                "comparison": "exact",
                "nullable": False,
                "tolerances": {"absolute": "0", "relative": "0"},
            },
        ],
        "limits": {
            "min_sources": 2,
            "max_sources": 2,
            "max_age_seconds": 60,
            "max_future_skew_seconds": 0,
            "max_records_per_source": 3,
            "max_line_bytes": 1024,
            "max_member_bytes": 4096,
            "require_distinct_origin_groups": True,
            **limits,
        },
    }


def _write_policy(tmp_path: Path, **limits: object) -> tuple[Path, ReleasePolicy]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy_document(**limits)), encoding="utf-8")
    return path, load_policy(path)


def _source_document(records: bytes, **overrides: object) -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.source.v1",
        "source_id": "source-a",
        "origin_group": "origin-a",
        "role": "candidate",
        "collected_at": "2035-01-02T03:04:05Z",
        "records": {
            "path": "records.jsonl",
            "sha256": hashlib.sha256(records).hexdigest(),
            "byte_count": len(records),
            "record_count": records.count(b"\n"),
        },
        **overrides,
    }


def _write_source(
    tmp_path: Path,
    records: bytes = b'{"item_id":"item-001","quantity":7}\n',
    **overrides: object,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    directory = tmp_path / "source-a"
    directory.mkdir()
    (directory / "records.jsonl").write_bytes(records)
    (directory / "source.json").write_bytes(
        json.dumps(_source_document(records, **overrides), separators=(",", ":")).encode()
    )
    return directory


def _assert_code(error: pytest.ExceptionInfo[InputError], code: ErrorCode) -> None:
    assert error.value.code is code


def test_load_policy_and_source_return_verified_immutable_batch(tmp_path: Path) -> None:
    policy_path, policy = _write_policy(tmp_path)
    source_directory = _write_source(tmp_path)

    assert load_policy(policy_path).dataset_id == "synthetic.inventory.v1"
    batch = load_source(source_directory.absolute(), policy=policy)

    assert isinstance(batch, SourceBatch)
    assert batch.source_id == "source-a"
    assert batch.collected_at.isoformat() == "2035-01-02T03:04:05+00:00"
    assert (
        batch.source_manifest_sha256
        == hashlib.sha256((source_directory / "source.json").read_bytes()).hexdigest()
    )
    assert (
        batch.records_member.sha256
        == hashlib.sha256((source_directory / "records.jsonl").read_bytes()).hexdigest()
    )
    assert batch.records_member.byte_count == len(b'{"item_id":"item-001","quantity":7}\n')
    assert batch.records_member.record_count == 1
    assert tuple(batch.records[0].items()) == (("item_id", "item-001"), ("quantity", 7))
    with pytest.raises(AttributeError):
        setattr(batch, "source_id", "changed")


@pytest.mark.parametrize(
    ("value", "message"),
    [("policy.json", "path"), (None, "path")],
)
def test_load_policy_requires_path(value: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        load_policy(value)  # type: ignore[arg-type]


def test_load_source_requires_path_directory_and_policy(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    with pytest.raises(ValueError, match="^directory$"):
        load_source("source-a", policy=policy)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^policy$"):
        load_source(tmp_path, policy=object())  # type: ignore[arg-type]


def test_load_policy_rejects_unsafe_inputs_without_leaking_content(tmp_path: Path) -> None:
    missing = tmp_path / "raw-secret-policy.json"
    with pytest.raises(InputError) as raised:
        load_policy(missing)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)

    unsafe = tmp_path / "policy.json"
    unsafe.write_text('{"leak":"raw-policy-sentinel"}', encoding="utf-8")
    with pytest.raises(InputError) as raised:
        load_policy(unsafe)
    _assert_code(raised, ErrorCode.INVALID_POLICY)
    assert str(tmp_path) not in str(raised.value)
    assert "raw-policy-sentinel" not in repr(raised.value)


def test_load_policy_rejects_symlink_nonregular_and_oversize(tmp_path: Path) -> None:
    policy_path, _ = _write_policy(tmp_path)
    link = tmp_path / "policy-link.json"
    link.symlink_to(policy_path)
    with pytest.raises(InputError) as raised:
        load_policy(link)
    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)

    with pytest.raises(InputError) as raised:
        load_policy(tmp_path)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)

    oversized = tmp_path / "oversized-policy.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(InputError) as raised:
        load_policy(oversized)
    _assert_code(raised, ErrorCode.RESOURCE_LIMIT_EXCEEDED)


def test_load_policy_rejects_an_intermediate_directory_symlink(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    _write_policy(real_parent)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(InputError) as raised:
        load_policy(linked_parent / "policy.json")

    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)


def test_load_policy_maps_read_io_failure_to_invalid_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path, _ = _write_policy(tmp_path)

    def deny_open(_: Path, __: int) -> int:
        raise PermissionError("raw-open-sentinel")

    monkeypatch.setattr("sourcequorum.source.os.open", deny_open)
    with pytest.raises(InputError) as raised:
        load_policy(policy_path)
    _assert_code(raised, ErrorCode.INVALID_POLICY)
    assert "raw-open-sentinel" not in str(raised.value)
    assert "raw-open-sentinel" not in repr(raised.value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda directory: (directory / "unexpected.txt").write_text("x", encoding="utf-8"),
        lambda directory: (directory / ".hidden").write_text("x", encoding="utf-8"),
        lambda directory: (directory / "unexpected-dir").mkdir(),
        lambda directory: (directory / "source.json").unlink(),
        lambda directory: (directory / "records.jsonl").unlink(),
    ],
)
def test_load_source_rejects_missing_or_unexpected_tree_members(
    tmp_path: Path, mutate: Any
) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path)
    mutate(directory)
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)


def test_load_source_rejects_final_and_member_symlinks(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(InputError) as raised:
        load_source(root_link, policy=policy)
    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)

    (directory / "records.jsonl").unlink()
    (directory / "records.jsonl").symlink_to(tmp_path / "outside-records.jsonl")
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)

    directory = _write_source(tmp_path / "source-member")
    (directory / "source.json").unlink()
    (directory / "source.json").symlink_to(tmp_path / "outside-source.json")
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)


@pytest.mark.parametrize("member", ["source.json", "records.jsonl"])
def test_load_source_rejects_directory_in_place_of_approved_member(
    tmp_path: Path, member: str
) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path)
    (directory / member).unlink()
    (directory / member).mkdir()
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)


def test_load_source_rejects_intermediate_symlink(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    target = _write_source(tmp_path)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(InputError) as raised:
        load_source(linked_parent / target.name, policy=policy)
    _assert_code(raised, ErrorCode.SYMLINK_FORBIDDEN)


@pytest.mark.parametrize(
    "records_override",
    [
        {"path": "/records.jsonl"},
        {"path": "../records.jsonl"},
        {"path": "other.jsonl"},
        {"sha256": "0" * 64},
        {"byte_count": 1},
        {"record_count": 2},
    ],
)
def test_load_source_rejects_manifest_member_mismatches(
    tmp_path: Path, records_override: dict[str, object]
) -> None:
    _, policy = _write_policy(tmp_path)
    records = b'{"item_id":"item-001","quantity":7}\n'
    manifest = _source_document(records)
    records_manifest = manifest["records"]
    assert isinstance(records_manifest, dict)
    manifest["records"] = {**records_manifest, **records_override}
    directory = _write_source(tmp_path, records)
    (directory / "source.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    expected = (
        ErrorCode.INVALID_SOURCE_MANIFEST
        if "path" in records_override
        else ErrorCode.SOURCE_HASH_MISMATCH
    )
    _assert_code(raised, expected)


def test_load_source_rejects_duplicate_manifest_keys_and_naive_timestamp(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    records = b'{"item_id":"item-001","quantity":7}\n'
    directory = _write_source(tmp_path, records)
    valid_manifest = json.dumps(_source_document(records), separators=(",", ":")).encode()
    (directory / "source.json").write_bytes(
        valid_manifest.replace(
            b'{"schema_version"',
            b'{"source_id":"source-a","source_id":"source-a","schema_version"',
            1,
        )
    )
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.INVALID_SOURCE_MANIFEST)

    directory = _write_source(tmp_path / "fresh", collected_at="2035-01-02T03:04:05")
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.INVALID_SOURCE_MANIFEST)


@pytest.mark.parametrize(
    "records",
    [
        b"",
        b"\n",
        b'{"item_id":"item-001","quantity":7}',
        b'{"item_id":"item-001","quantity":7}\r\n',
        b'{"item_id":"item-001","quantity":7,"quantity":8}\n',
        b'["item-001"]\n',
        b"not-json\n",
    ],
)
def test_load_source_rejects_invalid_jsonl_framing_and_values(
    tmp_path: Path, records: bytes
) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path, records)
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.JSONL_INVALID)


def test_load_source_rejects_unknown_and_missing_record_fields(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path, b'{"item_id":"item-001","unknown":7}\n')
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RECORD_SCHEMA_MISMATCH)

    directory = _write_source(tmp_path / "only-missing", b'{"item_id":"item-001"}\n')
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RECORD_SCHEMA_MISMATCH)

    directory = _write_source(
        tmp_path / "missing", b'{"item_id":"item-001","quantity":7,"extra":8}\n'
    )
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RECORD_SCHEMA_MISMATCH)


def test_load_source_rejects_duplicate_composite_key_without_value_leak(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    records = b'{"item_id":"raw-record-sentinel","quantity":7}\n' * 2
    directory = _write_source(tmp_path, records)
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.DUPLICATE_RECORD_KEY)
    assert "raw-record-sentinel" not in str(raised.value)
    assert "raw-record-sentinel" not in repr(raised.value)


def test_load_source_enforces_line_member_and_record_limits(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path, max_line_bytes=10)
    directory = _write_source(tmp_path, b'{"item_id":"item-001","quantity":7}\n')
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RESOURCE_LIMIT_EXCEEDED)

    _, policy = _write_policy(tmp_path / "source-member", max_member_bytes=10)
    directory = _write_source(tmp_path / "source-member")
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RESOURCE_LIMIT_EXCEEDED)

    _, policy = _write_policy(tmp_path / "member", max_member_bytes=512)
    directory = _write_source(
        tmp_path / "member", b'{"item_id":"item-001","quantity":"x"}\n' + b" " * 600
    )
    assert (directory / "source.json").stat().st_size <= policy.max_member_bytes
    assert (directory / "records.jsonl").stat().st_size > policy.max_member_bytes
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RESOURCE_LIMIT_EXCEEDED)

    _, policy = _write_policy(tmp_path / "records", max_records_per_source=1)
    directory = _write_source(
        tmp_path / "records",
        b'{"item_id":"item-001","quantity":7}\n{"item_id":"item-002","quantity":8}\n',
    )
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.RESOURCE_LIMIT_EXCEEDED)


def test_load_source_streams_records_without_path_read_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, policy = _write_policy(tmp_path)
    directory = _write_source(tmp_path)

    original_read_bytes = Path.read_bytes

    def fail_read_bytes(path: Path) -> bytes:
        if path == directory / "records.jsonl":
            raise AssertionError("Path.read_bytes must not load records")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    assert load_source(directory, policy=policy).source_id == "source-a"


def test_load_source_rejects_unsafe_directory_error_without_path_or_raw_json(
    tmp_path: Path,
) -> None:
    _, policy = _write_policy(tmp_path)
    directory = tmp_path / "raw-directory-sentinel"
    with pytest.raises(InputError) as raised:
        load_source(directory, policy=policy)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)
    assert str(directory) not in str(raised.value)
    assert "raw-directory-sentinel" not in repr(raised.value)


def test_load_source_maps_invalid_path_representation_without_leaking_it(tmp_path: Path) -> None:
    _, policy = _write_policy(tmp_path)
    sentinel = "raw-dir-sentinel\x00source"
    with pytest.raises(InputError) as raised:
        load_source(Path(sentinel), policy=policy)
    _assert_code(raised, ErrorCode.UNSAFE_PATH)
    assert sentinel not in str(raised.value)
    assert sentinel not in repr(raised.value)
