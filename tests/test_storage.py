"""Integration tests for immutable, atomic local release storage."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from sourcequorum import (
    CommitError,
    ComparisonMode,
    ErrorCode,
    FieldRule,
    ReleasePolicy,
    SourceBatch,
    SourceRole,
    ValueType,
)
from sourcequorum.publish import prepare_release


AT = datetime(2042, 6, 7, 8, 9, 10, tzinfo=UTC)


def _prepared() -> Any:
    """Build a real immutable release fixture for filesystem tests."""
    policy = ReleasePolicy(
        "sourcequorum.policy.v1",
        "storage.test",
        ("id",),
        (
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule(
                "amount", ValueType.DECIMAL_STRING, ComparisonMode.NUMERIC, False, Decimal(0)
            ),
        ),
    )
    records = ({"id": "one", "amount": "1"},)
    sources = tuple(
        SourceBatch(
            source_id,
            f"origin_{source_id}",
            role,
            AT,
            digest * 64,
            __import__("sourcequorum").MemberDigest("records.jsonl", "c" * 64, 1, 1),
            records,
        )
        for source_id, role, digest in (
            ("candidate", SourceRole.CANDIDATE, "a"),
            ("crosscheck", SourceRole.CROSSCHECK, "b"),
        )
    )
    return prepare_release(policy, sources, evaluated_at=AT)


def _assert_conflict(call: Any, raw: str = "RAW_STORAGE_SENTINEL") -> None:
    with pytest.raises(CommitError) as raised:
        call()
    assert raised.value.code is ErrorCode.IMMUTABLE_TARGET_CONFLICT
    assert raw not in str(raised.value) + repr(raised.value)


def test_commit_release_creates_the_exact_immutable_layout(tmp_path: Path) -> None:
    """A missing or extra member must not be mistaken for a committed release."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    result = commit_release(prepared, tmp_path)
    release = tmp_path / "releases" / prepared.release_id

    assert result.release_id == prepared.release_id
    assert result.release_directory == release
    assert {entry.relative_to(release).as_posix() for entry in release.rglob("*")} == {
        "manifest.json",
        "policy.json",
        "data",
        "data/records.jsonl",
        "reports",
        "reports/gate-report.json",
    }
    assert not (tmp_path / "latest").exists()
    assert not (tmp_path / "current").exists()
    for member, content in prepared.files.items():
        assert (release / member).read_bytes() == content


@pytest.mark.parametrize("value, message", [(object(), "prepared"), (None, "prepared")])
def test_commit_release_requires_a_prepared_release(
    value: object, message: str, tmp_path: Path
) -> None:
    """Accepting a lookalike would bypass the immutable prepared snapshot."""
    from sourcequorum.storage import commit_release

    with pytest.raises(ValueError, match=f"^{message}$"):
        commit_release(value, tmp_path)  # type: ignore[arg-type]


def test_commit_release_requires_a_path_output_root() -> None:
    """A string root could receive surprising path coercion before safety checks."""
    from sourcequorum.storage import commit_release

    with pytest.raises(ValueError, match="^output_root$"):
        commit_release(_prepared(), "RAW_STORAGE_SENTINEL")  # type: ignore[arg-type]


@pytest.mark.parametrize("shape", ["root_link", "releases_link", "target_link", "member_link"])
def test_commit_release_rejects_symlinks_at_every_release_boundary(
    tmp_path: Path, shape: str
) -> None:
    """Following any release-boundary symlink could write outside the chosen root."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    root = tmp_path / "root"
    root.mkdir()
    if shape == "root_link":
        link = tmp_path / "root-link"
        link.symlink_to(root, target_is_directory=True)
        _assert_conflict(lambda: commit_release(prepared, link), str(link))
        return
    releases = root / "releases"
    if shape == "releases_link":
        outside = tmp_path / "outside"
        outside.mkdir()
        releases.symlink_to(outside, target_is_directory=True)
    else:
        releases.mkdir()
        target = releases / prepared.release_id
        if shape == "target_link":
            target.symlink_to(tmp_path / "outside", target_is_directory=True)
        else:
            target.mkdir()
            (target / "manifest.json").symlink_to(tmp_path / "outside-member")
    _assert_conflict(lambda: commit_release(prepared, root), str(root))


def test_commit_release_rejects_a_symlinked_intermediate_root_component(tmp_path: Path) -> None:
    """A safe final root is insufficient when a parent component redirects writes."""
    from sourcequorum.storage import commit_release

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    root = real_parent / "root"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)

    _assert_conflict(lambda: commit_release(_prepared(), alias / "root"), str(alias))


@pytest.mark.parametrize("shape", ["root_file", "releases_file", "target_file", "member_directory"])
def test_commit_release_rejects_non_directory_roots_and_nonregular_members(
    tmp_path: Path, shape: str
) -> None:
    """Wrong node types must fail closed instead of being replaced or followed."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    root = tmp_path / "root"
    if shape == "root_file":
        root.write_bytes(b"RAW_STORAGE_SENTINEL")
    else:
        root.mkdir()
        releases = root / "releases"
        if shape == "releases_file":
            releases.write_bytes(b"x")
        else:
            releases.mkdir()
            target = releases / prepared.release_id
            target.mkdir()
            if shape == "target_file":
                target.rmdir()
                target.write_bytes(b"x")
            else:
                (target / "manifest.json").mkdir()
    _assert_conflict(lambda: commit_release(prepared, root), str(root))


def test_commit_release_stages_and_renames_under_the_same_releases_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cross-directory rename can lose the atomic publication guarantee."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    observed: list[tuple[Path, Path]] = []
    real_replace = os.replace

    def checked_replace(source: Path | str, destination: Path | str) -> None:
        observed.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr("sourcequorum.storage.os.replace", checked_replace)
    storage.commit_release(prepared, tmp_path)

    assert observed == [
        (tmp_path / "releases" / observed[0][0].name, tmp_path / "releases" / prepared.release_id)
    ]
    assert observed[0][0].parent == observed[0][1].parent == tmp_path / "releases"
    assert observed[0][0].name.startswith(".sourcequorum-stage-")


def test_commit_release_fsyncs_each_file_and_created_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skipping fsync leaves a successful return without the promised local durability steps."""
    import sourcequorum.storage as storage

    opened_paths: dict[int, Path] = {}
    synced_paths: list[Path] = []
    real_open = os.open
    real_close = os.close
    real_fsync = os.fsync

    def recording_open(path: Path | str, flags: int, mode: int = 0o777) -> int:
        fd = real_open(path, flags, mode)
        opened_paths[fd] = Path(path)
        return fd

    def recording_fsync(fd: int) -> None:
        synced_paths.append(opened_paths[fd])
        real_fsync(fd)

    def recording_close(fd: int) -> None:
        real_close(fd)
        opened_paths.pop(fd, None)

    monkeypatch.setattr("sourcequorum.storage.os.open", recording_open)
    monkeypatch.setattr("sourcequorum.storage.os.fsync", recording_fsync)
    monkeypatch.setattr("sourcequorum.storage.os.close", recording_close)
    prepared = _prepared()
    storage.commit_release(prepared, tmp_path)

    stage = next(path for path in synced_paths if path.name.startswith(".sourcequorum-stage-"))
    lock = next(path for path in synced_paths if path.name.startswith(".sourcequorum-lock-"))
    assert synced_paths == [
        tmp_path,
        lock,
        stage / "manifest.json",
        stage / "policy.json",
        stage / "data" / "records.jsonl",
        stage / "reports" / "gate-report.json",
        stage / "data",
        stage / "reports",
        stage,
        tmp_path / "releases",
    ]


@pytest.mark.parametrize("operation", ["mkdir", "open", "write", "flush", "fsync", "rename"])
def test_pre_rename_failure_cleans_only_its_owned_staging_and_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """A failed pre-publication write must not leave a partial release or erase neighbors."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    root = tmp_path / "root"
    root.mkdir()
    releases = root / "releases"
    releases.mkdir()
    neighbor = releases / "unrelated"
    neighbor.mkdir()
    (neighbor / "keep").write_bytes(b"keep")
    sentinel = "RAW_STORAGE_SENTINEL"

    if operation == "mkdir":
        real_mkdir = os.mkdir
        calls = 0

        def fail_mkdir(path: Path | str, mode: int = 0o777) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(sentinel)
            real_mkdir(path, mode)

        monkeypatch.setattr("sourcequorum.storage.os.mkdir", fail_mkdir)
    elif operation == "open":
        real_open = os.open

        def fail_open(path: Path | str, flags: int, mode: int = 0o777) -> int:
            if flags & os.O_WRONLY:
                raise OSError(sentinel)
            return real_open(path, flags, mode)

        monkeypatch.setattr("sourcequorum.storage.os.open", fail_open)
    elif operation == "write":
        monkeypatch.setattr(
            "sourcequorum.storage.os.write",
            lambda _fd, _data: (_ for _ in ()).throw(OSError(sentinel)),
        )
    elif operation == "flush":
        monkeypatch.setattr(
            storage, "_flush_file", lambda _fd: (_ for _ in ()).throw(OSError(sentinel))
        )
    elif operation == "fsync":
        monkeypatch.setattr(
            "sourcequorum.storage.os.fsync", lambda _fd: (_ for _ in ()).throw(OSError(sentinel))
        )
    else:
        monkeypatch.setattr(
            "sourcequorum.storage.os.replace",
            lambda _source, _target: (_ for _ in ()).throw(OSError(sentinel)),
        )

    _assert_conflict(lambda: storage.commit_release(prepared, root), sentinel)
    assert not (releases / prepared.release_id).exists()
    assert (neighbor / "keep").read_bytes() == b"keep"
    assert not [item for item in releases.iterdir() if item.name.startswith(".sourcequorum-")]


@pytest.mark.parametrize("operation", ["mkdir", "open", "write", "flush", "fsync"])
def test_injected_failure_after_partial_staging_cleans_owned_nodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """Failures after staging starts remove the partial tree and preserve unrelated siblings."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    releases = tmp_path / "releases"
    releases.mkdir()
    unrelated = releases / "unrelated"
    unrelated.write_bytes(b"keep")
    sentinel = "RAW_PARTIAL_SENTINEL"
    real_mkdir = os.mkdir
    real_open = os.open
    real_write = os.write
    real_fsync = os.fsync
    fd_paths: dict[int, Path] = {}

    def tracking_open(path: Path | str, flags: int, mode: int = 0o777) -> int:
        candidate = Path(path)
        if operation == "open" and candidate.name == "policy.json":
            assert (candidate.parent / "manifest.json").is_file()
            raise OSError(sentinel)
        fd = real_open(path, flags, mode)
        fd_paths[fd] = candidate
        return fd

    def delayed_mkdir(path: Path | str, mode: int = 0o777) -> None:
        candidate = Path(path)
        if operation == "mkdir" and candidate.name == "data":
            assert candidate.parent.name.startswith(".sourcequorum-stage-")
            assert candidate.parent.is_dir()
            raise OSError(sentinel)
        real_mkdir(path, mode)

    def delayed_write(fd: int, data: bytes) -> int:
        candidate = fd_paths.get(fd)
        if operation == "write" and candidate is not None and candidate.name == "policy.json":
            assert (candidate.parent / "manifest.json").is_file()
            raise OSError(sentinel)
        return real_write(fd, data)

    def delayed_fsync(fd: int) -> None:
        candidate = fd_paths.get(fd)
        if operation == "fsync" and candidate is not None and candidate.name == "policy.json":
            assert (candidate.parent / "manifest.json").is_file()
            raise OSError(sentinel)
        real_fsync(fd)

    real_flush = storage._flush_file

    def delayed_flush(fd: int) -> None:
        candidate = fd_paths.get(fd)
        if operation == "flush" and candidate is not None and candidate.name == "policy.json":
            assert (candidate.parent / "manifest.json").is_file()
            raise OSError(sentinel)
        real_flush(fd)

    monkeypatch.setattr("sourcequorum.storage.os.mkdir", delayed_mkdir)
    monkeypatch.setattr("sourcequorum.storage.os.open", tracking_open)
    monkeypatch.setattr("sourcequorum.storage.os.write", delayed_write)
    monkeypatch.setattr("sourcequorum.storage.os.fsync", delayed_fsync)
    monkeypatch.setattr(storage, "_flush_file", delayed_flush)

    _assert_conflict(lambda: storage.commit_release(prepared, tmp_path), sentinel)
    assert unrelated.read_bytes() == b"keep"
    assert not (releases / prepared.release_id).exists()
    assert {path.name for path in releases.iterdir()} == {"unrelated"}


@pytest.mark.parametrize("mutation", ["bytes", "extra", "hidden", "missing", "hardlink", "symlink"])
def test_existing_release_is_idempotent_only_for_an_exact_unlinked_regular_tree(
    tmp_path: Path, mutation: str
) -> None:
    """Any differing bytes or tree shape must remain immutable rather than be repaired."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    commit_release(prepared, tmp_path)
    release = tmp_path / "releases" / prepared.release_id
    if mutation == "bytes":
        (release / "policy.json").write_bytes(b"changed")
    elif mutation == "extra":
        (release / "extra.txt").write_bytes(b"x")
    elif mutation == "hidden":
        (release / ".hidden").write_bytes(b"x")
    elif mutation == "missing":
        (release / "data" / "records.jsonl").unlink()
    elif mutation == "hardlink":
        original = release / "policy.json"
        linked = tmp_path / "outside-hardlink"
        os.link(original, linked)
    else:
        member = release / "policy.json"
        member.unlink()
        member.symlink_to(tmp_path / "outside")
    _assert_conflict(lambda: commit_release(prepared, tmp_path), str(tmp_path))


@pytest.mark.parametrize("node", ["data", "reports", "policy.json"])
def test_existing_release_rejects_intermediate_and_member_symlinks(
    tmp_path: Path, node: str
) -> None:
    """Exact-looking targets must reject both intermediate and final symlinks."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    commit_release(prepared, tmp_path)
    release = tmp_path / "releases" / prepared.release_id
    outside = tmp_path / "outside"
    outside.mkdir()
    if node == "data":
        member = release / "data" / "records.jsonl"
        member.unlink()
        (release / "data").rmdir()
        (outside / "records.jsonl").write_bytes(prepared.files["data/records.jsonl"])
        (release / "data").symlink_to(outside, target_is_directory=True)
    elif node == "reports":
        member = release / "reports" / "gate-report.json"
        member.unlink()
        (release / "reports").rmdir()
        (outside / "gate-report.json").write_bytes(prepared.files["reports/gate-report.json"])
        (release / "reports").symlink_to(outside, target_is_directory=True)
    else:
        member = release / node
        member.unlink()
        outside_member = outside / node
        outside_member.write_bytes(prepared.files[node])
        member.symlink_to(outside_member)

    _assert_conflict(lambda: commit_release(prepared, tmp_path), str(outside))


def test_identical_existing_release_returns_without_content_writes_or_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recommitting matching bytes must validate the immutable target without changing it."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    storage.commit_release(prepared, tmp_path)

    attempts: list[str] = []

    def unexpected(name: str) -> Any:
        def fail(*_args: object, **_kwargs: object) -> object:
            attempts.append(name)
            raise AssertionError(f"unexpected mutation: {name}")

        return fail

    real_open = os.open

    def readonly_open(path: Path | str, flags: int, mode: int = 0o777) -> int:
        if flags & (os.O_WRONLY | os.O_CREAT | os.O_EXCL):
            attempts.append("open-for-write")
            raise AssertionError("unexpected mutation: open-for-write")
        return real_open(path, flags, mode)

    monkeypatch.setattr("sourcequorum.storage.os.open", readonly_open)
    for name in ("mkdir", "unlink", "rmdir", "replace", "write", "fsync"):
        monkeypatch.setattr(f"sourcequorum.storage.os.{name}", unexpected(name))
    monkeypatch.setattr(storage, "_flush_file", unexpected("flush"))
    assert storage.commit_release(prepared, tmp_path).release_directory.name == prepared.release_id
    assert attempts == []


def test_target_completed_between_initial_check_and_lock_is_validated_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The under-lock recheck accepts a cooperating writer's completed exact target."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    releases = tmp_path / "releases"
    real_create_lock = storage._create_lock

    def create_lock_then_publish(lock_path: Path) -> Any:
        owned = real_create_lock(lock_path)
        target = releases / prepared.release_id
        (target / "data").mkdir(parents=True)
        (target / "reports").mkdir()
        for member, content in prepared.files.items():
            (target / member).write_bytes(content)
        return owned

    monkeypatch.setattr(storage, "_create_lock", create_lock_then_publish)
    result = storage.commit_release(prepared, tmp_path)

    assert result.release_directory == releases / prepared.release_id
    assert not [path for path in releases.iterdir() if path.name.startswith(".sourcequorum-")]


def test_successful_commit_reports_lock_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A visible release with an owned lock left behind is not a successful commit call."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    real_unlink = os.unlink

    def fail_lock_unlink(path: Path | str) -> None:
        if Path(path).name.startswith(".sourcequorum-lock-"):
            raise OSError("RAW_LOCK_UNLINK_SENTINEL")
        real_unlink(path)

    monkeypatch.setattr("sourcequorum.storage.os.unlink", fail_lock_unlink)
    _assert_conflict(lambda: storage.commit_release(prepared, tmp_path), "RAW_LOCK_UNLINK_SENTINEL")
    release = tmp_path / "releases" / prepared.release_id
    assert release.is_dir()
    names = {path.name for path in (tmp_path / "releases").iterdir()}
    lock_name = next(name for name in names if name.startswith(".sourcequorum-lock-"))
    assert names == {lock_name, prepared.release_id}


@pytest.mark.parametrize("cleanup", ["file_unlink", "nested_rmdir", "stage_rmdir"])
def test_partial_stage_cleanup_failure_is_safe_and_ownership_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup: str
) -> None:
    """Cleanup failures report SQ400 and leave only the exact nodes they could not remove."""
    import sourcequorum.storage as storage

    prepared = _prepared()
    releases = tmp_path / "releases"
    releases.mkdir()
    unrelated = releases / "unrelated"
    unrelated.write_bytes(b"keep")
    real_replace = os.replace
    real_unlink = os.unlink
    real_rmdir = os.rmdir

    def fail_publication(source: Path | str, destination: Path | str) -> None:
        if Path(destination).name == prepared.release_id:
            raise OSError("RAW_PRIMARY_SENTINEL")
        real_replace(source, destination)

    def selective_unlink(path: Path | str) -> None:
        if cleanup == "file_unlink" and Path(path).name == "policy.json":
            raise OSError("RAW_CLEANUP_SENTINEL")
        real_unlink(path)

    def selective_rmdir(path: Path | str) -> None:
        candidate = Path(path)
        if cleanup == "nested_rmdir" and candidate.name == "data":
            raise OSError("RAW_CLEANUP_SENTINEL")
        if cleanup == "stage_rmdir" and candidate.name.startswith(".sourcequorum-stage-"):
            raise OSError("RAW_CLEANUP_SENTINEL")
        real_rmdir(path)

    monkeypatch.setattr("sourcequorum.storage.os.replace", fail_publication)
    monkeypatch.setattr("sourcequorum.storage.os.unlink", selective_unlink)
    monkeypatch.setattr("sourcequorum.storage.os.rmdir", selective_rmdir)
    _assert_conflict(lambda: storage.commit_release(prepared, tmp_path), "RAW_CLEANUP_SENTINEL")

    assert unrelated.read_bytes() == b"keep"
    assert not (releases / prepared.release_id).exists()
    assert not [path for path in releases.iterdir() if path.name.startswith(".sourcequorum-lock-")]
    stages = [path for path in releases.iterdir() if path.name.startswith(".sourcequorum-stage-")]
    assert len(stages) == 1
    survivors = {path.relative_to(stages[0]).as_posix() for path in stages[0].rglob("*")}
    if cleanup == "file_unlink":
        assert survivors == {"policy.json"}
    elif cleanup == "nested_rmdir":
        assert survivors == {"data"}
    else:
        assert survivors == set()


def test_preexisting_per_release_lock_fails_closed(tmp_path: Path) -> None:
    """A second cooperating committer must not race an in-progress release commit."""
    from sourcequorum.storage import commit_release

    prepared = _prepared()
    releases = tmp_path / "releases"
    releases.mkdir()
    lock_token = hashlib.sha256(prepared.release_id.encode("ascii")).hexdigest()
    lock = releases / f".sourcequorum-lock-{lock_token}"
    lock.write_bytes(b"")

    _assert_conflict(lambda: commit_release(prepared, tmp_path), str(tmp_path))
    assert lock.is_file()
