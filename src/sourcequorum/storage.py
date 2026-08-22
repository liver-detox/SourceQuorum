"""Immutable, atomic release storage on a trusted local filesystem.

The implementation coordinates cooperating local writers and rejects observed
symlinks and unexpected nodes.  It does not claim resistance to a malicious
concurrent filesystem actor, nor crash-proof distributed transaction semantics.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import CommitError, ErrorCode
from .models import CommitResult, PreparedRelease


_MEMBERS = (
    "manifest.json",
    "policy.json",
    "data/records.jsonl",
    "reports/gate-report.json",
)
_STAGE_PREFIX = ".sourcequorum-stage-"
_LOCK_PREFIX = ".sourcequorum-lock-"
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
_FILE_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True, slots=True)
class _OwnedNode:
    path: Path
    device: int
    inode: int


def commit_release(prepared: PreparedRelease, output_root: Path) -> CommitResult:
    """Atomically commit a prepared release below an existing trusted local root.

    This is a fail-closed local filesystem boundary for cooperating writers. It
    intentionally does not promise safety against a malicious concurrent actor
    changing filesystem entries, or a crash-proof distributed transaction.
    """
    if not isinstance(prepared, PreparedRelease):
        raise ValueError("prepared")
    if not isinstance(output_root, Path):
        raise ValueError("output_root")

    stage: _OwnedNode | None = None
    lock: _OwnedNode | None = None
    renamed = False
    try:
        _require_real_directory(output_root)
        releases = output_root / "releases"
        if _path_absent(releases):
            os.mkdir(releases, 0o700)
            _fsync_directory(output_root)
        _require_real_directory(releases)

        target = releases / prepared.release_id
        if not _path_absent(target):
            _verify_existing_target(target, prepared.files)
            return CommitResult(prepared.release_id, target)

        lock_path = releases / _lock_name(prepared.release_id)
        lock = _create_lock(lock_path)
        if not _path_absent(target):
            _verify_existing_target(target, prepared.files)
            return CommitResult(prepared.release_id, target)

        stage_path = releases / f"{_STAGE_PREFIX}{uuid.uuid4().hex}"
        os.mkdir(stage_path, 0o700)
        stage = _owned_node(stage_path)
        _require_owned_stage(stage, releases)
        _write_stage(stage.path, prepared.files)
        _fsync_directory(stage.path / "data")
        _fsync_directory(stage.path / "reports")
        _fsync_directory(stage.path)
        os.replace(stage.path, target)
        renamed = True
        stage = None
        _fsync_directory(releases)
        return CommitResult(prepared.release_id, target)
    except CommitError:
        raise
    except Exception:
        raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT) from None
    finally:
        cleanup_complete = True
        if not renamed and stage is not None:
            cleanup_complete = _remove_owned_stage(stage, output_root / "releases")
        if lock is not None:
            cleanup_complete = (
                _remove_owned_lock(lock, output_root / "releases") and cleanup_complete
            )
        if not cleanup_complete:
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT) from None


def _lock_name(release_id: str) -> str:
    """Return a private fixed-shape lock name without user path components."""
    return _LOCK_PREFIX + hashlib.sha256(release_id.encode("ascii")).hexdigest()


def _path_absent(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _require_real_directory(path: Path) -> None:
    _require_no_symlink_components(path)
    node = os.lstat(path)
    if stat.S_ISLNK(node.st_mode) or not stat.S_ISDIR(node.st_mode):
        raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)


def _require_no_symlink_components(path: Path) -> None:
    """Reject every lexical component without resolving or following it."""
    lexical = path if path.is_absolute() else Path.cwd() / path
    current = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        current /= component
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)


def _create_lock(lock: Path) -> _OwnedNode:
    fd = os.open(lock, _FILE_WRITE_FLAGS, 0o600)
    opened = os.fstat(fd)
    owned = _OwnedNode(lock, opened.st_dev, opened.st_ino)
    try:
        _flush_file(fd)
        os.close(fd)
        return owned
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        _remove_owned_lock(owned, lock.parent)
        raise


def _owned_node(path: Path) -> _OwnedNode:
    node = os.lstat(path)
    return _OwnedNode(path, node.st_dev, node.st_ino)


def _write_stage(stage: Path, files: Mapping[str, bytes]) -> None:
    os.mkdir(stage / "data", 0o700)
    os.mkdir(stage / "reports", 0o700)
    for member in _MEMBERS:
        content = files[member]
        if type(content) is not bytes:
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)
        _write_new_file(stage / member, content)


def _write_new_file(path: Path, content: bytes) -> None:
    fd = os.open(path, _FILE_WRITE_FLAGS, 0o600)
    try:
        _write_all(fd, content)
        _flush_file(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(fd, content[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _flush_file(fd: int) -> None:
    os.fsync(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, _DIRECTORY_FLAGS)
    try:
        node = os.fstat(fd)
        if not stat.S_ISDIR(node.st_mode):
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_existing_target(target: Path, files: Mapping[str, bytes]) -> None:
    _require_real_directory(target)
    expected_root = {"manifest.json", "policy.json", "data", "reports"}
    if _entry_names(target) != expected_root:
        raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)
    for directory, expected in (("data", {"records.jsonl"}), ("reports", {"gate-report.json"})):
        child = target / directory
        _require_real_directory(child)
        if _entry_names(child) != expected:
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)
    for member in _MEMBERS:
        content = files[member]
        if type(content) is not bytes or not _matches_regular_file(target / member, content):
            raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)


def _entry_names(directory: Path) -> set[str]:
    with os.scandir(directory) as entries:
        return {entry.name for entry in entries}


def _matches_regular_file(path: Path, expected: bytes) -> bool:
    node = os.lstat(path)
    if stat.S_ISLNK(node.st_mode) or not stat.S_ISREG(node.st_mode) or node.st_nlink != 1:
        return False
    if node.st_size != len(expected):
        return False
    fd = os.open(path, _FILE_READ_FLAGS)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != len(expected)
        ):
            return False
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks) == expected
    finally:
        os.close(fd)


def _require_owned_stage(stage: _OwnedNode, releases: Path) -> None:
    if stage.path.parent != releases or not stage.path.name.startswith(_STAGE_PREFIX):
        raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)
    node = os.lstat(stage.path)
    if (
        stat.S_ISLNK(node.st_mode)
        or not stat.S_ISDIR(node.st_mode)
        or node.st_dev != stage.device
        or node.st_ino != stage.inode
    ):
        raise CommitError(ErrorCode.IMMUTABLE_TARGET_CONFLICT)


def _remove_owned_stage(stage: _OwnedNode, releases: Path) -> bool:
    """Remove only this call's known, verified staging nodes after a failed commit."""
    try:
        _require_owned_stage(stage, releases)
    except Exception:
        return False

    complete = True
    for member in _MEMBERS:
        path = stage.path / member
        try:
            if not _path_absent(path):
                node = os.lstat(path)
                if stat.S_ISREG(node.st_mode) and not stat.S_ISLNK(node.st_mode):
                    os.unlink(path)
                else:
                    complete = False
        except Exception:
            complete = False
    for directory in (stage.path / "data", stage.path / "reports"):
        try:
            if not _path_absent(directory):
                node = os.lstat(directory)
                if stat.S_ISDIR(node.st_mode) and not stat.S_ISLNK(node.st_mode):
                    os.rmdir(directory)
                else:
                    complete = False
        except Exception:
            complete = False
    try:
        os.rmdir(stage.path)
    except Exception:
        complete = False
    return complete and _path_absent(stage.path)


def _remove_owned_lock(lock: _OwnedNode, releases: Path) -> bool:
    """Remove only a regular lock created by this call under the verified parent."""
    try:
        if lock.path.parent != releases or not lock.path.name.startswith(_LOCK_PREFIX):
            return False
        node = os.lstat(lock.path)
        if (
            not stat.S_ISREG(node.st_mode)
            or stat.S_ISLNK(node.st_mode)
            or node.st_dev != lock.device
            or node.st_ino != lock.inode
        ):
            return False
        os.unlink(lock.path)
        return _path_absent(lock.path)
    except FileNotFoundError:
        return False
    except Exception:
        return False
