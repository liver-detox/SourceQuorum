"""End-to-end contracts for the checked-in, deliberately synthetic example."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

from sourcequorum.canonical import dumps_canonical
from sourcequorum.cli import main


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "inventory"
AT = "2040-01-15T00:05:00+00:00"


def _assert_fixture_privacy(example: Path) -> None:
    for path in example.rglob("*"):
        assert not path.is_symlink()
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").casefold()
        assert not re.search(r"/(?:users|home|tmp|private|volumes)/", text)
        assert not re.search(r"(?:^|[^a-z])[a-z]:\\", text)
        assert not re.search(r"\\\\[^\\]+\\", text)
        assert "file:" not in text
        assert "mother project" not in text
        assert "internal workspace" not in text


def _assert_safe_workflow(workflow: str) -> None:
    lower = workflow.casefold()
    assert "permissions: {}" in lower
    assert len(re.findall(r"(?m)^\s*permissions\s*:", lower)) == 1
    assert "write-all" not in lower
    assert not re.search(
        r"(?m)^\s*(?:contents|id-token|pull-requests|packages|actions)\s*:\s*write\s*$", lower
    )
    forbidden_fetch = (
        "http://",
        "https://",
        "curl ",
        "wget ",
        "git clone",
        "urllib",
        "requests",
        "httpx",
    )
    assert not any(pattern in lower for pattern in forbidden_fetch)


def _run(example: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    result = main(
        [
            "check",
            "--policy",
            str(example / "policy.json"),
            "--source",
            str(example / "candidate"),
            "--source",
            str(example / "crosscheck"),
            "--at",
            AT,
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    return result, captured.out


def test_synthetic_inventory_is_accepted_and_one_changed_value_is_sq209(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Changing only the crosscheck quantity must turn the real gate into SQ209."""
    accepted, output = _run(EXAMPLE, capsys)
    assert accepted == 0
    assert json.loads(output)["status"] == "ACCEPTED"

    copied = tmp_path / "inventory"
    shutil.copytree(EXAMPLE, copied)
    records_path = copied / "crosscheck" / "records.jsonl"
    changed = b'{"item_id":"widget_alpha","quantity":7}\n{"item_id":"widget_beta","quantity":12}\n'
    records_path.write_bytes(changed)
    source_path = copied / "crosscheck" / "source.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["records"].update(
        {
            "sha256": hashlib.sha256(changed).hexdigest(),
            "byte_count": len(changed),
            "record_count": 2,
        }
    )
    source_path.write_bytes(dumps_canonical(source))

    rejected, output = _run(copied, capsys)
    report = json.loads(output)
    assert rejected == 1
    assert report["status"] == "REJECTED"
    assert [finding["code"] for finding in report["findings"]] == ["SQ209"]


def test_cli_quickstart_publishes_then_runs_both_verification_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A published synthetic release verifies intrinsically and with source replay."""
    releases = tmp_path / "releases"
    publish_args = [
        "publish",
        "--policy",
        str(EXAMPLE / "policy.json"),
        "--source",
        str(EXAMPLE / "candidate"),
        "--source",
        str(EXAMPLE / "crosscheck"),
        "--at",
        AT,
        "--output",
        str(tmp_path),
        "--commit",
        "--json",
    ]
    assert main(publish_args) == 0
    release_id = json.loads(capsys.readouterr().out)["release_id"]
    release_dir = releases / release_id

    assert main(["verify", str(release_dir), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    replay = [
        "verify",
        str(release_dir),
        "--source",
        str(EXAMPLE / "candidate"),
        "--source",
        str(EXAMPLE / "crosscheck"),
        "--json",
    ]
    assert main(replay) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    changed_sources = tmp_path / "changed-sources"
    shutil.copytree(EXAMPLE, changed_sources)
    changed_records = changed_sources / "crosscheck" / "records.jsonl"
    changed_records.write_bytes(
        b'{"item_id":"widget_alpha","quantity":7}\n{"item_id":"widget_beta","quantity":12}\n'
    )

    assert main(["verify", str(release_dir), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    changed_replay = [
        "verify",
        str(release_dir),
        "--source",
        str(changed_sources / "candidate"),
        "--source",
        str(changed_sources / "crosscheck"),
        "--json",
    ]
    assert main(changed_replay) == 3
    output = capsys.readouterr().out
    assert json.loads(output)["findings"] == [{"code": "SQ104"}]
    assert "12" not in output
    assert str(changed_sources) not in output


def _json_lines(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_example_documents_equal_the_independently_frozen_fixture() -> None:
    """Any added identifier, field, date, or numeric value must fail the fixture contract."""
    expected_policy = {
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
            "max_age_seconds": 3600,
            "max_future_skew_seconds": 3600,
            "max_records_per_source": 16,
            "max_line_bytes": 1024,
            "max_member_bytes": 8192,
            "require_distinct_origin_groups": True,
        },
    }
    expected_records = [
        {"item_id": "widget_alpha", "quantity": 7},
        {"item_id": "widget_beta", "quantity": 11},
    ]
    records_bytes = (
        b'{"item_id":"widget_alpha","quantity":7}\n{"item_id":"widget_beta","quantity":11}\n'
    )
    expected_sources = {
        "candidate": {
            "schema_version": "sourcequorum.source.v1",
            "source_id": "demo_candidate",
            "origin_group": "fictional_origin_a",
            "role": "candidate",
            "collected_at": "2040-01-15T00:00:00Z",
        },
        "crosscheck": {
            "schema_version": "sourcequorum.source.v1",
            "source_id": "demo_crosscheck",
            "origin_group": "fictional_origin_b",
            "role": "crosscheck",
            "collected_at": "2040-01-15T00:00:00Z",
        },
    }

    assert json.loads((EXAMPLE / "policy.json").read_bytes()) == expected_policy
    for role, expected_source in expected_sources.items():
        directory = EXAMPLE / role
        assert {path.name for path in directory.iterdir()} == {"source.json", "records.jsonl"}
        assert all(path.is_file() and not path.is_symlink() for path in directory.iterdir())
        assert (directory / "records.jsonl").read_bytes() == records_bytes
        assert _json_lines(directory / "records.jsonl") == expected_records
        source = json.loads((directory / "source.json").read_bytes())
        assert source == {
            **expected_source,
            "records": {
                "path": "records.jsonl",
                "sha256": "65eb456a26c451f14d2e90b171f5c7665791dadb15f4d92eb21fe086b8c39715",
                "byte_count": 80,
                "record_count": 2,
            },
        }


def test_example_text_has_no_path_leakage_or_sensitive_context() -> None:
    """Absolute paths, URLs, provider names, and sensitive domains must be rejected."""
    forbidden = (
        "http",
        "www.",
        "provider",
        "account",
        "holding",
        "trade",
        "financial",
        "return",
        "profit",
        "secret",
        "token",
        "user",
        "private",
        "\\" + "users" + "\\",
        "/users/",
        "file:",
    )
    for path in EXAMPLE.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").casefold()
        assert not any(term in text for term in forbidden)
        assert re.search(r"(?<![0-9])[0-9]{6}(?![0-9])", text) is None


def test_fixture_privacy_rejects_symlinks_before_reading(tmp_path: Path) -> None:
    """Replacing either a directory or file with a symlink must fail before content reads."""
    for relative in ("candidate", "candidate/source.json"):
        copied = tmp_path / relative.replace("/", "-")
        shutil.copytree(EXAMPLE, copied)
        target = copied / relative
        replacement = copied / f"replacement-{target.name}"
        target.rename(replacement)
        target.symlink_to(replacement, target_is_directory=replacement.is_dir())
        with pytest.raises(AssertionError):
            _assert_fixture_privacy(copied)


@pytest.mark.parametrize(
    "sentinel",
    [
        "/" + "Users/sample/work",
        "/" + "home/sample/work",
        "/tmp/sample",
        "/private/sample",
        "/Volumes/sample",
        "C:" + r"\\" + "sample" + r"\\" + "work",
        r"\\" + r"\\" + "server" + r"\\" + "share",
        "file:///sample/work",
        "mother project workspace",
        "internal workspace",
    ],
)
def test_fixture_privacy_rejects_path_and_workspace_sentinels(
    tmp_path: Path, sentinel: str
) -> None:
    """Every frozen path/provenance sentinel must fail in a real copied fixture."""
    copied = tmp_path / "inventory"
    shutil.copytree(EXAMPLE, copied)
    source_path = copied / "candidate" / "source.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["source_id"] = sentinel
    source_path.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_fixture_privacy(copied)


def test_ci_is_manual_read_only_and_has_no_external_or_distribution_side_effects() -> None:
    """Adding an automatic trigger, write authority, network fetch, or release step must fail."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").lower()
    _assert_safe_workflow(workflow)
    lines = workflow.splitlines()
    assert all(version in workflow for version in ("3.11", "3.12", "3.13", "3.14"))
    on_index = lines.index("on:")
    permissions_index = lines.index("permissions: {}")
    assert [line.strip() for line in lines[on_index + 1 : permissions_index] if line.strip()] == [
        "workflow_dispatch:"
    ]
    assert "permissions: {}" in workflow
    workflow_without_local_auditor_path = workflow.replace("scripts/audit_release.py", "")
    assert not any(
        word in workflow_without_local_auditor_path
        for word in (
            "http://",
            "https://",
            "curl ",
            "wget ",
            "git clone",
            "upload",
            "publish",
            "release",
            "secrets.",
            "provider",
            "external dataset",
        )
    )
    assert set(re.findall(r"uses:\s*([^\s]+)", workflow)) == {
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    }
    assert "pytest tests/test_distribution_members.py tests/test_synthetic_example.py" in workflow


@pytest.mark.parametrize(
    "mutation",
    [
        "permissions: write-all",
        "permissions:\n  contents: write",
        "permissions:\n  id-" + "token" + ": write",
        "permissions:\n  pull-requests: write",
        "permissions:\n  packages: write",
        "permissions:\n  actions: write",
        "jobs:\n  verify:\n    permissions:\n      contents: write",
        "jobs:\n  verify:\n    permissions: write-all",
        "run: curl sample.invalid",
        "run: wget sample.invalid",
        "run: python -c 'import urllib.request'",
        "run: python -c 'import requests'",
        "run: python -c 'import httpx'",
        "run: git clone sample.invalid",
        "run: pip install package@" + "https" + "://sample.invalid/archive.whl",
        "run: sh -c 'curl sample.invalid'",
    ],
)
def test_workflow_mutations_reject_write_permissions_and_external_fetch(mutation: str) -> None:
    """Each realistic permission or fetch mutation must fail the workflow audit."""
    baseline = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_safe_workflow(f"{baseline}\n{mutation}\n")


def test_workflow_audit_allows_local_development_dependency_install() -> None:
    """Normal action setup and local development dependency installation remain allowed."""
    baseline = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    _assert_safe_workflow(baseline.replace("pip install .[dev]", "pip install -e .[dev]"))
