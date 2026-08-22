"""Contract tests for read-only full-chain release verification."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, overload

import pytest

import sourcequorum
from sourcequorum import (
    ComparisonMode,
    ErrorCode,
    FieldRule,
    MemberDigest,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)
from sourcequorum.canonical import dumps_canonical, loads_strict, sha256_bytes
from sourcequorum.publish import prepare_release
from sourcequorum.storage import commit_release


AT = datetime(2042, 6, 7, 8, 9, 10, 123456, tzinfo=UTC)


def _policy() -> ReleasePolicy:
    return ReleasePolicy(
        "sourcequorum.policy.v1",
        "verify.test",
        ("id",),
        (
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule("amount", ValueType.DECIMAL_STRING, ComparisonMode.NUMERIC, False),
        ),
    )


def _prepared() -> Any:
    records = ({"id": "one", "amount": "1"},)
    sources = (
        SourceBatch(
            "candidate",
            "origin_candidate",
            SourceRole.CANDIDATE,
            AT,
            "a" * 64,
            MemberDigest("records.jsonl", "c" * 64, 26, 1),
            records,
        ),
        SourceBatch(
            "crosscheck",
            "origin_crosscheck",
            SourceRole.CROSSCHECK,
            AT,
            "b" * 64,
            MemberDigest("records.jsonl", "c" * 64, 26, 1),
            records,
        ),
    )
    return prepare_release(_policy(), sources, evaluated_at=AT)


def _stored_release(tmp_path: Path) -> Path:
    result = commit_release(_prepared(), tmp_path)
    return result.release_directory


def _verify(release_dir: Path, *, source_dirs: object = ()) -> Any:
    return sourcequorum.verify_release(release_dir, source_dirs=source_dirs)  # type: ignore[arg-type]


class _FalseyReplaySequence(Sequence[Path]):
    def __init__(self, paths: tuple[Path, ...]) -> None:
        self._paths = paths
        self.iterations = 0

    @overload
    def __getitem__(self, index: int) -> Path: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[Path]: ...

    def __getitem__(self, index: int | slice) -> Path | Sequence[Path]:
        return self._paths[index]

    def __len__(self) -> int:
        return 0

    def __iter__(self) -> Iterator[Path]:
        self.iterations += 1
        return iter(self._paths)


def _tree_state(root: Path) -> dict[str, tuple[int, int, int, int]]:
    return {
        path.relative_to(root).as_posix(): (info.st_mode, info.st_ino, info.st_size, info.st_nlink)
        for path in (root, *root.rglob("*"))
        for info in (path.lstat(),)
    }


def _assert_invalid(release: Path, code: ErrorCode, sentinel: str = "RAW_VERIFY_SENTINEL") -> None:
    result = _verify(release)
    assert not result.valid
    assert result.release_id is None
    assert result.findings[0].code is code
    assert str(release) not in repr(result)
    assert sentinel not in repr(result)


def test_verify_release_accepts_a_stored_release_without_any_filesystem_mutation(
    tmp_path: Path,
) -> None:
    """Writing, repairing, or omitting a valid chain must make this test fail."""
    release = _stored_release(tmp_path)
    before = _tree_state(release)

    result = _verify(release)

    assert result.valid
    assert result.release_id == release.name
    assert result.findings == ()
    assert _tree_state(release) == before


@pytest.mark.parametrize("value", ["release", None])
def test_verify_release_requires_a_path(value: object) -> None:
    """Coercing untrusted release names instead of rejecting them must fail this test."""
    with pytest.raises(ValueError, match="^release_dir$"):
        _verify(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["source", ["source"], [Path("source"), "source"], None])
def test_verify_release_requires_a_path_sequence_for_source_replay(
    value: object, tmp_path: Path
) -> None:
    """Accepting string-like or non-Path source evidence must fail this test."""
    with pytest.raises(ValueError, match="^source_dirs$"):
        _verify(_stored_release(tmp_path), source_dirs=value)


@pytest.mark.parametrize(
    ("member", "replacement"),
    [
        ("manifest.json", b'{"raw":"RAW_VERIFY_SENTINEL"}'),
        ("policy.json", b'{"raw":"RAW_VERIFY_SENTINEL"}'),
        ("reports/gate-report.json", b'{"raw":"RAW_VERIFY_SENTINEL"}'),
        ("data/records.jsonl", b'{"raw":"RAW_VERIFY_SENTINEL"}\n'),
    ],
)
def test_verify_release_rejects_each_independently_tampered_member(
    tmp_path: Path, member: str, replacement: bytes
) -> None:
    """Skipping a member digest or full chain binding must fail this test."""
    release = _stored_release(tmp_path)
    (release / member).write_bytes(replacement)

    _assert_invalid(
        release,
        ErrorCode.MANIFEST_INVALID if member == "manifest.json" else ErrorCode.MEMBER_TAMPERED,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda release: (release / "manifest.json").unlink(),
        lambda release: (release / "data" / "records.jsonl").unlink(),
    ],
)
def test_verify_release_rejects_missing_members(
    tmp_path: Path, mutate: Callable[[Path], None]
) -> None:
    """Treating a partial release as complete must fail this test."""
    release = _stored_release(tmp_path)
    mutate(release)

    _assert_invalid(release, ErrorCode.MEMBER_MISSING)


@pytest.mark.parametrize("name", ["extra.txt", ".hidden"])
def test_verify_release_rejects_extra_and_hidden_members(tmp_path: Path, name: str) -> None:
    """Ignoring undeclared release nodes must fail this test."""
    release = _stored_release(tmp_path)
    (release / name).write_text("RAW_VERIFY_SENTINEL", encoding="utf-8")

    _assert_invalid(release, ErrorCode.UNEXPECTED_MEMBER)


@pytest.mark.parametrize("shape", ["root", "member", "intermediate"])
def test_verify_release_rejects_symlinks_at_every_release_boundary(
    tmp_path: Path, shape: str
) -> None:
    """Following any symlink while checking a release must fail this test."""
    release = _stored_release(tmp_path)
    if shape == "root":
        alias = tmp_path / "raw-release-link"
        alias.symlink_to(release, target_is_directory=True)
        target = alias
    elif shape == "member":
        member = release / "policy.json"
        member.unlink()
        member.symlink_to(tmp_path / "raw-outside-policy.json")
        target = release
    else:
        data = release / "data"
        data.rename(tmp_path / "real-data")
        data.symlink_to(tmp_path / "real-data", target_is_directory=True)
        target = release

    _assert_invalid(target, ErrorCode.SYMLINK_FORBIDDEN)


def _rebuild_manifest(release: Path, manifest: dict[str, Any]) -> None:
    """Build a deliberately self-consistent forged manifest for verifier tests only."""
    member_bytes = {
        "policy.json": (release / "policy.json").read_bytes(),
        "data/records.jsonl": (release / "data" / "records.jsonl").read_bytes(),
        "reports/gate-report.json": (release / "reports" / "gate-report.json").read_bytes(),
    }
    manifest["policy"].update(
        sha256=sha256_bytes(member_bytes["policy.json"]),
        byte_count=len(member_bytes["policy.json"]),
    )
    manifest["gate"].update(
        report_sha256=sha256_bytes(member_bytes["reports/gate-report.json"]),
        byte_count=len(member_bytes["reports/gate-report.json"]),
    )
    for member in manifest["members"]:
        content = member_bytes[member["path"]]
        member.update(sha256=sha256_bytes(content), byte_count=len(content))
    manifest_without_id = dict(manifest)
    del manifest_without_id["release_id"]
    manifest["release_id"] = "sq-v1-" + sha256_bytes(dumps_canonical(manifest_without_id))
    (release / "manifest.json").write_bytes(dumps_canonical(manifest))


def _commit_forged_manifest(release: Path, manifest: dict[str, Any]) -> Path:
    """Move a forged self-consistent release beneath its forged identity name."""
    _rebuild_manifest(release, manifest)
    forged = release.with_name(manifest["release_id"])
    release.rename(forged)
    return forged


def _commit_reidentified_manifest(release: Path, manifest: dict[str, Any]) -> Path:
    """Persist a canonical forged manifest without repairing its declared members."""
    without_id = dict(manifest)
    del without_id["release_id"]
    manifest["release_id"] = "sq-v1-" + sha256_bytes(dumps_canonical(without_id))
    (release / "manifest.json").write_bytes(dumps_canonical(manifest))
    forged = release.with_name(manifest["release_id"])
    release.rename(forged)
    return forged


def _forge_policy(release: Path, mutate: Callable[[dict[str, Any]], None]) -> Path:
    """Persist a canonical schema-shaped policy forgery and rebuild its release identity."""
    policy = loads_strict((release / "policy.json").read_bytes())
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(policy, dict)
    assert isinstance(manifest, dict)
    mutate(policy)
    (release / "policy.json").write_bytes(dumps_canonical(policy))
    return _commit_forged_manifest(release, manifest)


def test_verify_release_rejects_a_self_consistent_noncanonical_policy_forgery(
    tmp_path: Path,
) -> None:
    """Accepting syntactically valid but noncanonical bytes must fail this test."""
    release = _stored_release(tmp_path)
    policy = loads_strict((release / "policy.json").read_bytes())
    assert isinstance(policy, dict)
    (release / "policy.json").write_bytes(json.dumps(policy, indent=1).encode())
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    forged = _commit_forged_manifest(release, manifest)

    _assert_invalid(forged, ErrorCode.MANIFEST_INVALID)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda policy: policy["fields"].append(dict(policy["fields"][0])),
        lambda policy: policy.update(key_fields=["missing"]),
    ],
)
def test_verify_release_rejects_schema_valid_but_model_invalid_policy(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    """Skipping ReleasePolicy invariants when replay is absent must fail this test."""
    release = _stored_release(tmp_path)
    forged = _forge_policy(release, mutate)

    _assert_invalid(forged, ErrorCode.MANIFEST_INVALID)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest: manifest["members"][0].update(media_type="application/json"),
        lambda manifest: manifest["members"][0].update(record_count=99),
        lambda manifest: manifest["selection"].update(candidate_source_id="crosscheck"),
        lambda manifest: manifest["sources"][0].update(origin_group="origin_crosscheck"),
    ],
)
def test_verify_release_rejects_self_consistent_member_and_source_semantic_forgeries(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    """Skipping deep PreparedRelease bindings must fail this test."""
    release = _stored_release(tmp_path)
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    mutate(manifest)
    forged = _commit_forged_manifest(release, manifest)

    _assert_invalid(forged, ErrorCode.MANIFEST_INVALID)


def test_verify_release_rejects_a_reidentified_member_size_declaration(tmp_path: Path) -> None:
    """Trusting a declared byte count without comparing the file must fail this test."""
    release = _stored_release(tmp_path)
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    members = manifest["members"]
    assert isinstance(members, list)
    member = members[1]
    assert isinstance(member, dict)
    member["byte_count"] = 0
    forged = _commit_reidentified_manifest(release, manifest)

    _assert_invalid(forged, ErrorCode.MEMBER_TAMPERED)


@pytest.mark.parametrize(
    "contents",
    [b'{"amount":"1","id":"one"}\r\n', b'\n{"amount":"1","id":"one"}\n'],
)
def test_verify_release_rejects_a_self_consistent_noncanonical_data_forgery(
    tmp_path: Path, contents: bytes
) -> None:
    """Accepting CRLF or blank JSONL framing with recomputed digests must fail this test."""
    release = _stored_release(tmp_path)
    (release / "data" / "records.jsonl").write_bytes(contents)
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    forged = _commit_forged_manifest(release, manifest)

    _assert_invalid(forged, ErrorCode.MANIFEST_INVALID)


@pytest.mark.parametrize("shape", ["hardlink", "fifo"])
def test_verify_release_rejects_non_single_link_and_nonregular_members(
    tmp_path: Path, shape: str
) -> None:
    """Treating hardlinked or special members as immutable files must fail this test."""
    release = _stored_release(tmp_path)
    member = release / "policy.json"
    if shape == "hardlink":
        os.link(member, release / "policy-copy.json")
    else:
        member.unlink()
        os.mkfifo(member)

    _assert_invalid(
        release,
        ErrorCode.UNEXPECTED_MEMBER if shape == "hardlink" else ErrorCode.UNSAFE_PATH,
    )


def test_verify_release_rejects_a_hardlinked_required_member_even_without_an_extra_name(
    tmp_path: Path,
) -> None:
    """Checking only the tree names but not link count must fail this test."""
    release = _stored_release(tmp_path)
    member = release / "policy.json"
    linked = tmp_path / "linked-policy"
    os.link(member, linked)

    _assert_invalid(release, ErrorCode.MEMBER_TAMPERED)


def test_verify_release_reports_source_evidence_replay_mismatch_without_source_leaks(
    tmp_path: Path,
) -> None:
    """Accepting missing source evidence or rendering its contents must fail this test."""
    policy = _policy()
    source_dirs = _write_replay_sources(tmp_path, policy)
    from sourcequorum.source import load_source

    sources = tuple(load_source(path, policy=policy) for path in source_dirs)
    output = tmp_path / "out"
    output.mkdir()
    release = commit_release(prepare_release(policy, sources, evaluated_at=AT), output)

    result = _verify(release.release_directory, source_dirs=(source_dirs[0],))

    assert not result.valid
    assert result.findings == (sourcequorum.Finding(ErrorCode.SOURCE_HASH_MISMATCH),)
    assert str(source_dirs[0]) not in repr(result)


@pytest.mark.parametrize("shape", ["extra", "duplicate"])
def test_verify_release_rejects_extra_and_duplicate_source_replay_directories(
    tmp_path: Path, shape: str
) -> None:
    """Comparing only a set of replayed IDs without cardinality must fail this test."""
    policy, source_dirs, release = _stored_replay_release(tmp_path)
    del policy
    supplied = (*source_dirs, source_dirs[0])
    if shape == "extra":
        supplied = (*source_dirs, _write_extra_source(tmp_path))

    result = _verify(release, source_dirs=supplied)

    assert result.findings == (sourcequorum.Finding(ErrorCode.SOURCE_HASH_MISMATCH),)


@pytest.mark.parametrize("member", ["source.json", "records.jsonl"])
def test_verify_release_rejects_tampered_source_replay_evidence(
    tmp_path: Path, member: str
) -> None:
    """Ignoring a changed source manifest or data member must fail this test."""
    _, source_dirs, release = _stored_replay_release(tmp_path)
    (source_dirs[0] / member).write_bytes(b"RAW_SOURCE_REPLAY_SENTINEL")

    result = _verify(release, source_dirs=source_dirs)

    assert result.findings == (sourcequorum.Finding(ErrorCode.SOURCE_HASH_MISMATCH),)
    assert "RAW_SOURCE_REPLAY_SENTINEL" not in repr(result)
    assert str(source_dirs[0]) not in repr(result)


def test_verify_release_replays_a_falsey_source_sequence_from_one_snapshot(tmp_path: Path) -> None:
    """Removing the single snapshot or reusing source_dirs after it must fail this test."""
    _, source_dirs, release = _stored_replay_release(tmp_path)
    (source_dirs[0] / "records.jsonl").write_bytes(b"RAW_SOURCE_REPLAY_SENTINEL")
    supplied = _FalseyReplaySequence(source_dirs)

    result = _verify(release, source_dirs=supplied)

    assert result.findings == (sourcequorum.Finding(ErrorCode.SOURCE_HASH_MISMATCH),)
    assert supplied.iterations == 1


def test_verify_release_rejects_replay_against_forged_stored_source_declaration(
    tmp_path: Path,
) -> None:
    """Replaying only source IDs while ignoring stored declarations must fail this test."""
    _, source_dirs, release = _stored_replay_release(tmp_path)
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    sources = manifest["sources"]
    assert isinstance(sources, list)
    source = sources[0]
    assert isinstance(source, dict)
    source["source_manifest_sha256"] = "f" * 64
    forged = _commit_forged_manifest(release, manifest)

    result = _verify(forged, source_dirs=source_dirs)

    assert result.findings == (sourcequorum.Finding(ErrorCode.SOURCE_HASH_MISMATCH),)


def test_verify_release_rejects_a_directory_name_that_does_not_bind_to_the_release_id(
    tmp_path: Path,
) -> None:
    """Not binding the verified ID to the directory name must fail this test."""
    release = _stored_release(tmp_path)
    renamed = release.with_name("sq-v1-" + "0" * 64)
    release.rename(renamed)

    _assert_invalid(renamed, ErrorCode.RELEASE_ID_MISMATCH)


def test_verify_release_classifies_an_internally_false_id_as_release_id_mismatch(
    tmp_path: Path,
) -> None:
    """Mapping an internal identity mismatch to generic manifest failure must fail this test."""
    release = _stored_release(tmp_path)
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    false_id = "sq-v1-" + "0" * 64
    manifest["release_id"] = false_id
    (release / "manifest.json").write_bytes(dumps_canonical(manifest))
    renamed = release.with_name(false_id)
    release.rename(renamed)

    _assert_invalid(renamed, ErrorCode.RELEASE_ID_MISMATCH)


def test_verify_release_uses_no_mutation_primitives_on_a_valid_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any write/create flag or mutation primitive used by verification must fail this test."""
    release = _stored_release(tmp_path)
    real_open = os.open

    def read_only_open(path: Path | str, flags: int, *args: object) -> int:
        forbidden = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if flags & forbidden:
            raise AssertionError("filesystem mutation")
        return real_open(path, flags, *args)  # type: ignore[arg-type]

    def forbidden(*_: object, **__: object) -> object:
        raise AssertionError("filesystem mutation")

    monkeypatch.setattr("sourcequorum.verify.os.open", read_only_open)
    for name in ("write", "mkdir", "unlink", "rmdir", "rename", "replace"):
        monkeypatch.setattr(f"sourcequorum.verify.os.{name}", forbidden, raising=False)

    assert _verify(release).valid


@pytest.mark.parametrize("change", ["inode", "size", "type"])
def test_verify_release_fails_closed_when_opened_identity_changes_from_lstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Trusting a descriptor whose identity differs from lstat must fail this test."""
    release = _stored_release(tmp_path)
    real_fstat = os.fstat
    changed = False

    def inconsistent_fstat(fd: int) -> os.stat_result:
        nonlocal changed
        observed = real_fstat(fd)
        if changed:
            return observed
        changed = True
        values = list(observed)
        if change == "inode":
            values[1] += 1
        elif change == "size":
            values[6] += 1
        else:
            values[0] = stat.S_IFDIR | 0o700
        return os.stat_result(values)

    monkeypatch.setattr("sourcequorum.verify.os.fstat", inconsistent_fstat)

    _assert_invalid(release, ErrorCode.MEMBER_TAMPERED)


def test_verify_release_fails_closed_when_final_descriptor_size_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Omitting the post-read descriptor identity check must fail this test."""
    release = _stored_release(tmp_path)
    real_fstat = os.fstat
    calls = 0

    def changed_final_fstat(fd: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        observed = real_fstat(fd)
        if calls != 2:
            return observed
        values = list(observed)
        values[6] += 1
        return os.stat_result(values)

    monkeypatch.setattr("sourcequorum.verify.os.fstat", changed_final_fstat)

    _assert_invalid(release, ErrorCode.MEMBER_TAMPERED)


@pytest.mark.parametrize("failure", ["short", "eintr", "io"])
def test_verify_release_fails_closed_on_ambiguous_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Accepting a short, interrupted, or failed read must fail this test."""
    release = _stored_release(tmp_path)
    real_read = os.read
    calls = 0

    def ambiguous_read(fd: int, count: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            if failure == "short":
                return b""
            if failure == "eintr":
                raise InterruptedError("RAW_READ_SENTINEL")
            raise OSError("RAW_READ_SENTINEL")
        return real_read(fd, count)

    monkeypatch.setattr("sourcequorum.verify.os.read", ambiguous_read)

    _assert_invalid(release, ErrorCode.MEMBER_TAMPERED, "RAW_READ_SENTINEL")


@pytest.mark.parametrize("member", ["manifest.json", "reports/gate-report.json"])
def test_verify_release_rejects_noncanonical_manifest_and_report_documents(
    tmp_path: Path, member: str
) -> None:
    """Parsing without enforcing exact canonical bytes must fail this test."""
    release = _stored_release(tmp_path)
    path = release / member
    document = loads_strict(path.read_bytes())
    path.write_bytes(json.dumps(document, indent=1).encode())

    _assert_invalid(
        release,
        ErrorCode.MANIFEST_INVALID if member == "manifest.json" else ErrorCode.MEMBER_TAMPERED,
    )


def test_verify_release_rejects_self_consistent_noncanonical_report_bytes(tmp_path: Path) -> None:
    """Digest-valid but noncanonical report bytes must reach and fail canonical validation."""
    release = _stored_release(tmp_path)
    report_path = release / "reports" / "gate-report.json"
    report = loads_strict(report_path.read_bytes())
    report_path.write_bytes(json.dumps(report, indent=1).encode())
    manifest = loads_strict((release / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    forged = _commit_forged_manifest(release, manifest)

    _assert_invalid(forged, ErrorCode.MANIFEST_INVALID)


def test_verify_release_fails_closed_on_open_failure_without_leaking_os_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Returning valid after an unreadable member must fail this test."""
    release = _stored_release(tmp_path)

    def deny_open(*_: object, **__: object) -> int:
        raise PermissionError("RAW_OPEN_SENTINEL")

    monkeypatch.setattr("sourcequorum.verify.os.open", deny_open)

    _assert_invalid(release, ErrorCode.MEMBER_TAMPERED, "RAW_OPEN_SENTINEL")


def test_verify_release_can_replay_matching_source_evidence_in_any_input_order(
    tmp_path: Path,
) -> None:
    """Skipping source replay or making it order-sensitive must fail this test."""
    policy = _policy()
    source_dirs = _write_replay_sources(tmp_path, policy)
    from sourcequorum.source import load_source

    sources = tuple(load_source(path, policy=policy) for path in source_dirs)
    output = tmp_path / "out"
    output.mkdir()
    release = commit_release(prepare_release(policy, sources, evaluated_at=AT), output)

    result = _verify(release.release_directory, source_dirs=tuple(reversed(source_dirs)))

    assert result.valid
    assert result.release_id == release.release_id


def _write_replay_sources(root: Path, policy: ReleasePolicy) -> tuple[Path, Path]:
    records = b'{"amount":"1","id":"one"}\n'
    result: list[Path] = []
    for source_id, origin, role in (
        ("candidate", "origin_candidate", "candidate"),
        ("crosscheck", "origin_crosscheck", "crosscheck"),
    ):
        directory = root / source_id
        directory.mkdir()
        (directory / "records.jsonl").write_bytes(records)
        source = {
            "schema_version": "sourcequorum.source.v1",
            "source_id": source_id,
            "origin_group": origin,
            "role": role,
            "collected_at": "2042-06-07T08:09:10.123456Z",
            "records": {
                "path": "records.jsonl",
                "sha256": sha256_bytes(records),
                "byte_count": len(records),
                "record_count": 1,
            },
        }
        (directory / "source.json").write_bytes(dumps_canonical(source))
        result.append(directory)
    return tuple(result)  # type: ignore[return-value]


def _stored_replay_release(tmp_path: Path) -> tuple[ReleasePolicy, tuple[Path, Path], Path]:
    policy = _policy()
    source_dirs = _write_replay_sources(tmp_path, policy)
    from sourcequorum.source import load_source

    sources = tuple(load_source(path, policy=policy) for path in source_dirs)
    output = tmp_path / "out"
    output.mkdir()
    stored = commit_release(prepare_release(policy, sources, evaluated_at=AT), output)
    return policy, source_dirs, stored.release_directory


def _write_extra_source(root: Path) -> Path:
    records = b'{"amount":"1","id":"one"}\n'
    directory = root / "extra"
    directory.mkdir()
    (directory / "records.jsonl").write_bytes(records)
    document = {
        "schema_version": "sourcequorum.source.v1",
        "source_id": "extra",
        "origin_group": "origin_extra",
        "role": "crosscheck",
        "collected_at": "2042-06-07T08:09:10.123456Z",
        "records": {
            "path": "records.jsonl",
            "sha256": sha256_bytes(records),
            "byte_count": len(records),
            "record_count": 1,
        },
    }
    (directory / "source.json").write_bytes(dumps_canonical(document))
    return directory
