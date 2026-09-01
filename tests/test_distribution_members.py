"""Built-distribution allowlist contracts for the Phase A repository."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import zipfile
from email.parser import BytesParser


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.1"

PACKAGE_MEMBERS = {
    "__init__.py",
    "__main__.py",
    "canonical.py",
    "cli.py",
    "errors.py",
    "gate.py",
    "manifest.py",
    "models.py",
    "publish.py",
    "py.typed",
    "schema.py",
    "source.py",
    "storage.py",
    "verify.py",
    "_schemas/gate-report-v1.schema.json",
    "_schemas/policy-v1.schema.json",
    "_schemas/release-manifest-v1.schema.json",
    "_schemas/source-v1.schema.json",
}
TEST_MEMBERS = {
    "test_audit_release.py",
    "test_canonical.py",
    "test_cli.py",
    "test_distribution_members.py",
    "test_errors.py",
    "test_gate.py",
    "test_manifest.py",
    "test_models.py",
    "test_publish.py",
    "test_schema.py",
    "test_source.py",
    "test_storage.py",
    "test_synthetic_example.py",
    "test_verify.py",
}
PUBLIC_MEMBERS = {
    ".gitignore",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "dependency-register.json",
    "LICENSE",
    "NOTICE",
    "PRIVACY.md",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "docs/architecture.md",
    "docs/manifest-v1.md",
    "docs/threat-model.md",
    "examples/inventory/policy.json",
    "examples/inventory/candidate/records.jsonl",
    "examples/inventory/candidate/source.json",
    "examples/inventory/crosscheck/records.jsonl",
    "examples/inventory/crosscheck/source.json",
    "pyproject.toml",
    "public-allowlist.txt",
    "scripts/__init__.py",
    "scripts/audit_release.py",
    "scripts/demo.py",
    "sbom.cdx.json",
}


def _assert_safe_members(members: set[str], expected: set[str]) -> None:
    forbidden_parts = {
        ".superpowers",
        "superpowers",
        "internal",
        "private",
        "provenance",
        "plan",
        "plans",
        "report",
        "reports",
    }
    assert members == expected
    for member in members:
        parts = {PurePosixPath(part).stem.casefold() for part in PurePosixPath(member).parts}
        assert parts.isdisjoint(forbidden_parts)


def test_built_wheel_and_sdist_contain_only_approved_members(tmp_path: Path) -> None:
    """Adding any undeclared or internal path to either real artifact must fail."""
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(tmp_path.glob("*.whl"))
    sdist = next(tmp_path.glob("*.tar.gz"))
    dist_info = f"sourcequorum-{VERSION}.dist-info"
    expected_wheel = {f"sourcequorum/{member}" for member in PACKAGE_MEMBERS} | {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
    }
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = {name for name in archive.namelist() if not name.endswith("/")}
        wheel_metadata = BytesParser().parsebytes(archive.read(f"{dist_info}/METADATA"))
    _assert_safe_members(wheel_members, expected_wheel)
    assert wheel_metadata["License-Expression"] == "Apache-2.0"
    assert wheel_metadata["Author"] == "liver-detox"
    assert wheel_metadata.get_all("License-File") == ["LICENSE", "NOTICE"]
    assert wheel_metadata.get_all("Requires-Dist") == [
        "jsonschema<5,>=4.26",
        "rfc3339-validator<0.2,>=0.1.4",
        "rfc8785<0.2,>=0.1.4",
        "build==1.5.0; extra == 'dev'",
        "hatchling==1.31.0; extra == 'dev'",
        "mypy==2.3.0; extra == 'dev'",
        "pytest==9.1.1; extra == 'dev'",
        "ruff==0.15.22; extra == 'dev'",
    ]
    assert not any("LICENSE" + "-PENDING.md" in member for member in wheel_members)

    prefix = f"sourcequorum-{VERSION}/"
    expected_sdist = (
        {f"src/sourcequorum/{member}" for member in PACKAGE_MEMBERS}
        | {f"tests/{member}" for member in TEST_MEMBERS}
        | PUBLIC_MEMBERS
        | {"PKG-INFO"}
    )
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_members = {
            member.name.removeprefix(prefix) for member in archive.getmembers() if member.isfile()
        }
        pkg_info_member = archive.getmember(f"{prefix}PKG-INFO")
        pkg_info_stream = archive.extractfile(pkg_info_member)
        assert pkg_info_stream is not None
        pkg_info = BytesParser().parsebytes(pkg_info_stream.read())
    _assert_safe_members(sdist_members, expected_sdist)
    assert pkg_info["License-Expression"] == "Apache-2.0"
    assert pkg_info["Author"] == "liver-detox"
    assert pkg_info.get_all("License-File") == ["LICENSE", "NOTICE"]
    assert pkg_info.get_all("Requires-Dist") == [
        "jsonschema<5,>=4.26",
        "rfc3339-validator<0.2,>=0.1.4",
        "rfc8785<0.2,>=0.1.4",
        "build==1.5.0; extra == 'dev'",
        "hatchling==1.31.0; extra == 'dev'",
        "mypy==2.3.0; extra == 'dev'",
        "pytest==9.1.1; extra == 'dev'",
        "ruff==0.15.22; extra == 'dev'",
    ]
    assert "LICENSE" in sdist_members
    assert "NOTICE" in sdist_members
    assert not any("LICENSE" + "-PENDING.md" in member for member in sdist_members)
