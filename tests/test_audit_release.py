"""Behavior tests for the local, fail-closed release auditor."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import stat
import tarfile
import zipfile

import pytest

from scripts.audit_release import (
    _content_rule_ids,
    _git_object_scannable_content,
    AuditResult,
    audit_release,
    main,
)


RUNTIME_PROFILE = "cpython-3.12-reference-runtime"
COMPLETENESS_SCOPE = "python-package-runtime-distribution-closure-only"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON_SHA = "a26af69be951a213d495a4c3e4e4022e16d87065"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _approved_tree(
    tmp_path: Path, project_name: str = "samplepkg"
) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "approved"
    package_name = project_name.replace("-", "_")
    _write(root / "src" / package_name / "__init__.py", '"""Synthetic package."""\n')
    _write(
        root / "pyproject.toml",
        f'[project]\nname = "{project_name}"\nversion = "0.0.1"\n'
        'license = "Apache-2.0"\nlicense-files = ["LICENSE", "NOTICE"]\n'
        'authors = [{ name = "liver-detox" }]\n'
        'dependencies = ["sample-dep>=1,<2"]\n',
    )
    _write(root / "LICENSE", (Path(__file__).resolve().parents[1] / "LICENSE").read_text())
    _write(root / "NOTICE", "SourceQuorum\nCopyright 2026 liver-detox\n")
    _write(root / "PRIVACY.md", "Synthetic local privacy boundary.\n")
    _write(
        root / "dependency-register.json",
        json.dumps(
            {
                "status": "approved",
                "rights_status": "approved",
                "sbom_complete": True,
                "profile": RUNTIME_PROFILE,
                "completeness_scope": COMPLETENESS_SCOPE,
                "dependencies": [
                    {
                        "package": "sample-dep",
                        "version": "1.2.3",
                        "spdx": "MIT",
                        "source_url": "https" + "://pypi.org/project/sample-dep/1.2.3/",
                        "artifact_license_review": "approved",
                        "notice": "not-required",
                        "status": "approved",
                    }
                ],
            }
        ),
    )
    allowlist = root / "public-allowlist.txt"
    sbom = root / "sbom.cdx.json"
    _write(
        sbom,
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "component": {
                        "bom-ref": f"pkg:pypi/{project_name}@0.0.1",
                        "type": "library",
                        "name": project_name,
                        "version": "0.0.1",
                        "purl": f"pkg:pypi/{project_name}@0.0.1",
                        "licenses": [{"expression": "Apache-2.0"}],
                    },
                    "properties": [
                        {
                            "name": "sourcequorum:runtime-profile",
                            "value": RUNTIME_PROFILE,
                        },
                        {
                            "name": "sourcequorum:completeness-scope",
                            "value": COMPLETENESS_SCOPE,
                        },
                    ],
                },
                "components": [
                    {
                        "bom-ref": "pkg:pypi/sample-dep@1.2.3",
                        "type": "library",
                        "name": "sample-dep",
                        "version": "1.2.3",
                        "purl": "pkg:pypi/sample-dep@1.2.3",
                        "licenses": [{"license": {"id": "MIT"}}],
                    }
                ],
                "dependencies": [
                    {
                        "ref": f"pkg:pypi/{project_name}@0.0.1",
                        "dependsOn": ["pkg:pypi/sample-dep@1.2.3"],
                    },
                    {"ref": "pkg:pypi/sample-dep@1.2.3", "dependsOn": []},
                ],
            }
        ),
    )
    _write(
        allowlist,
        "LICENSE\nNOTICE\nPRIVACY.md\ndependency-register.json\npublic-allowlist.txt\npyproject.toml\nsbom.cdx.json\n"
        f"src/{package_name}/__init__.py\n",
    )
    return root, allowlist, root / "dependency-register.json", sbom


@pytest.mark.parametrize("mutation", ("missing", "tampered"))
def test_license_contract_reports_missing_or_tampered_root_license(
    tmp_path: Path, mutation: str
) -> None:
    """Skipping root-license presence or byte validation must let a broken grant pass."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    license_path = root / "LICENSE"
    if mutation == "missing":
        license_path.unlink()
    else:
        _write(license_path, "Apache License altered by a release mistake.\n")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    expected = "RG-LICENSE-MISSING" if mutation == "missing" else "RG-LICENSE-CONTENT"
    assert expected in result.rule_ids


def test_license_contract_reports_a_wrong_project_spdx_expression(tmp_path: Path) -> None:
    """Accepting a non-Apache project expression must misstate the outbound package grant."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    pyproject = root / "pyproject.toml"
    _write(
        pyproject,
        pyproject.read_text(encoding="utf-8").replace('license = "Apache-2.0"', 'license = "MIT"'),
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-PROJECT-LICENSE" in result.rule_ids


@pytest.mark.parametrize("mutation", ("missing", "placeholder"))
def test_license_contract_reports_missing_or_placeholder_notice(
    tmp_path: Path, mutation: str
) -> None:
    """Permitting an absent or placeholder NOTICE must hide an incomplete notice contract."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    notice_path = root / "NOTICE"
    if mutation == "missing":
        notice_path.unlink()
    else:
        _write(notice_path, "NOTICE pending review\n")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-NOTICE" in result.rule_ids


def test_artifact_license_contract_reports_mismatched_wheel_and_sdist_metadata(
    tmp_path: Path,
) -> None:
    """Ignoring artifact metadata must allow a wheel or sdist to advertise another license."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    wheel = _wheel_with_member(
        tmp_path,
        "samplepkg",
        "samplepkg-0.0.1.dist-info/METADATA",
        "Metadata-Version: 2.4\nLicense-Expression: MIT\nAuthor: liver-detox\n"
        "License-File: LICENSE\nLicense-File: NOTICE\n",
        "metadata-mismatch",
    )
    sdist = _sdist_with_member(
        tmp_path,
        "samplepkg",
        "PKG-INFO",
        "Metadata-Version: 2.4\nLicense-Expression: Apache-2.0\nAuthor: liver-detox\n"
        "License-File: LICENSE\n",
        "metadata-mismatch",
    )

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel, sdist),
    )

    assert "RG-ARTIFACT-LICENSE" in result.rule_ids


def _append_allowlist(allowlist: Path, *members: str) -> None:
    existing = allowlist.read_text(encoding="utf-8").splitlines()
    _write(allowlist, "\n".join(sorted([*existing, *members])) + "\n")


def _leak_payload(rule: str) -> str:
    payloads = (
        ("RG-CONTENT-PRIVATE-KEY", "-----BEGIN " + "PRIVATE KEY-----\nsynthetic"),
        ("RG-CONTENT-SECRET", "api_" + "key = SQ_" + "SYNTHETIC_123456789"),
        ("RG-CONTENT-PII", "synthetic.person" + "@example.invalid"),
        ("RG-CONTENT-ABSOLUTE", "/" + "Users/synthetic/work"),
        ("RG-CONTENT-SECURITY-ID", "security_" + "id: " + "123" + "456"),
        ("RG-CONTENT-URL", "https" + "://example.invalid/api"),
        ("RG-CONTENT-FINANCIAL", "broker_" + "account" + ": SYNTHETIC-1234"),
        ("RG-CONTENT-PROVIDER", "provider_" + "name: synthetic-cloud"),
    )
    return dict(payloads)[rule]


def _commit_all(
    root: Path, *, message: str = "synthetic", email: str = "synthetic@invalid"
) -> None:
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            f"user.email={email}",
            "commit",
            "-qm",
            message,
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)


def _write_git_object(root: Path, object_type: str, content: bytes) -> str:
    return (
        subprocess.run(
            ["git", "hash-object", "--literally", "-t", object_type, "-w", "--stdin"],
            cwd=root,
            check=True,
            input=content,
            capture_output=True,
        )
        .stdout.strip()
        .decode("ascii")
    )


def _wheel_with_member(
    tmp_path: Path, project_name: str, member: str, content: str, label: str
) -> Path:
    wheel = tmp_path / f"{project_name}-0.0.1-{label}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(member, content)
    return wheel


def _sdist_with_member(
    tmp_path: Path, project_name: str, member: str, content: str, label: str
) -> Path:
    sdist = tmp_path / f"{project_name}-0.0.1-{label}.tar.gz"
    payload = content.encode("utf-8")
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo(f"{project_name}-0.0.1/{member}")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return sdist


def _apache_metadata() -> bytes:
    return (
        b"Metadata-Version: 2.4\n"
        b"License-Expression: Apache-2.0\n"
        b"Author: liver-detox\n"
        b"License-File: LICENSE\n"
        b"License-File: NOTICE\n"
        b"Requires-Dist: sample-dep<2,>=1\n"
    )


def _complete_artifacts(
    tmp_path: Path,
    root: Path,
    allowlist: Path,
    wheel_requires: tuple[str, ...],
    sdist_requires: tuple[str, ...],
) -> tuple[Path, Path]:
    metadata_prefix = (
        "Metadata-Version: 2.4\n"
        "Name: samplepkg\n"
        "Version: 0.0.1\n"
        "License-Expression: Apache-2.0\n"
        "Author: liver-detox\n"
        "License-File: LICENSE\n"
        "License-File: NOTICE\n"
    )
    wheel = tmp_path / "samplepkg-0.0.1-py3-none-any.whl"
    wheel_members = {
        "samplepkg/__init__.py": (root / "src" / "samplepkg" / "__init__.py").read_bytes(),
        "samplepkg-0.0.1.dist-info/METADATA": (
            metadata_prefix + "".join(f"Requires-Dist: {value}\n" for value in wheel_requires)
        ).encode(),
        "samplepkg-0.0.1.dist-info/RECORD": b"",
        "samplepkg-0.0.1.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        "samplepkg-0.0.1.dist-info/entry_points.txt": b"",
        "samplepkg-0.0.1.dist-info/licenses/LICENSE": (root / "LICENSE").read_bytes(),
        "samplepkg-0.0.1.dist-info/licenses/NOTICE": (root / "NOTICE").read_bytes(),
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        for member, content in wheel_members.items():
            archive.writestr(member, content)

    sdist = tmp_path / "samplepkg-0.0.1.tar.gz"
    sdist_members = {
        "PKG-INFO": (
            metadata_prefix + "".join(f"Requires-Dist: {value}\n" for value in sdist_requires)
        ).encode(),
        "LICENSE": (root / "LICENSE").read_bytes(),
        "NOTICE": (root / "NOTICE").read_bytes(),
        "PRIVACY.md": (root / "PRIVACY.md").read_bytes(),
        "dependency-register.json": (root / "dependency-register.json").read_bytes(),
        "public-allowlist.txt": allowlist.read_bytes(),
        "pyproject.toml": (root / "pyproject.toml").read_bytes(),
        "sbom.cdx.json": (root / "sbom.cdx.json").read_bytes(),
        "src/samplepkg/__init__.py": (root / "src" / "samplepkg" / "__init__.py").read_bytes(),
    }
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in sdist_members.items():
            info = tarfile.TarInfo(f"samplepkg-0.0.1/{member}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return wheel, sdist


def test_approved_synthetic_tree_has_a_zero_exit_audit(tmp_path: Path) -> None:
    """Removing the approved status or an allowlisted member must block the fixture."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert result.public_release_ready is True
    assert result.rule_ids == ()
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "rule",
    [
        "RG-CONTENT-PRIVATE-KEY",
        "RG-CONTENT-SECRET",
        "RG-CONTENT-PII",
        "RG-CONTENT-ABSOLUTE",
        "RG-CONTENT-SECURITY-ID",
        "RG-CONTENT-URL",
        "RG-CONTENT-FINANCIAL",
        "RG-CONTENT-PROVIDER",
    ],
)
def test_unsafe_content_blocks_without_echoing_its_value(
    tmp_path: Path, rule: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deleting a content detector must make a secret-like unsafe file look releasable."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    relative = "notes.txt"
    _write(root / relative, _leak_payload(rule))
    _append_allowlist(allowlist, relative)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)
    exit_code = main(
        [
            str(root),
            "--allowlist",
            str(allowlist),
            "--register",
            str(register),
            "--sbom",
            str(sbom),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rule in result.rule_ids
    assert result.exit_code == 1
    assert exit_code == 1
    assert "SQ_SENTINEL" not in captured.out
    assert "SQ_SENTINEL" not in captured.err
    assert str(root) not in captured.out


@pytest.mark.parametrize(
    "text",
    [
        "no secrets or tokens are collected",
        "no account or personal data is collected",
        "use docs/example/config.json or ./relative/path",
        "SHA-256, version 1.2.3, and isolated identifier 123" + "456",
        "released 2026-08-13",
        "not financial advice; no account, return, profit, holding, or trading analysis",
        "no provider integration, domain lookup, endpoint configuration, or network access",
    ],
)
def test_public_rule_text_does_not_trigger_content_findings(tmp_path: Path, text: str) -> None:
    """Treating ordinary policy words, dates, or numbers as leaks must block public prose."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / "README.md", text)
    _append_allowlist(allowlist, "README.md")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert not any(rule.startswith("RG-CONTENT-") for rule in result.rule_ids)


@pytest.mark.parametrize(
    ("path", "blocked"),
    [
        (".gitignore", False),
        (".github/workflows/ci.yml", False),
        (".github", True),
        (".covert", True),
        ("docs/.covert", True),
        (".github/.covert", True),
    ],
)
def test_hidden_policy_has_only_two_exact_public_exceptions(
    tmp_path: Path, path: str, blocked: bool
) -> None:
    """Broadening dot-path exceptions must expose covert source members."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / path, "synthetic\n")
    _append_allowlist(allowlist, path)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert ("RG-SOURCE-HIDDEN" in result.rule_ids) is blocked


def test_schema_url_exception_is_exact_and_path_bound(tmp_path: Path) -> None:
    """A global URL exemption or a non-schema exception must permit an unapproved endpoint."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    schema_path = "src/sourcequorum/_schemas/example.schema.json"
    schema_url = "https" + "://json-schema.org/draft/2020-12/schema"
    _write(root / schema_path, json.dumps({"$schema": schema_url, "type": "object"}))
    _append_allowlist(allowlist, schema_path)

    allowed = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    _write(
        root / schema_path,
        json.dumps({"$schema": schema_url, "description": "https" + "://example.invalid/extra"}),
    )
    blocked = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)
    _write(root / "schema.json", json.dumps({"$schema": schema_url}))
    _append_allowlist(allowlist, "schema.json")
    wrong_path = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-CONTENT-URL" not in allowed.rule_ids
    assert "RG-CONTENT-URL" in blocked.rule_ids
    assert "RG-CONTENT-URL" in wrong_path.rule_ids


def test_candidate_like_public_text_has_no_content_false_positive(tmp_path: Path) -> None:
    """Scanning the auditor and public disclaimers must not make the gate self-trigger."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    schema_path = "src/sourcequorum/_schemas/example.schema.json"
    schema_url = "https" + "://json-schema.org/draft/2020-12/schema"
    auditor_source = Path("scripts/audit_release.py").read_text(encoding="utf-8")
    _write(
        root / "README.md",
        "No account or personal data. Not financial advice. "
        "No provider integration, trading analysis, or network access.\n",
    )
    _write(root / "scripts" / "auditor_source.py", auditor_source)
    _write(root / schema_path, json.dumps({"$schema": schema_url, "type": "object"}))
    _append_allowlist(allowlist, "README.md", "scripts/auditor_source.py", schema_path)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert not any(rule.startswith("RG-CONTENT-") for rule in result.rule_ids)


def test_current_allowlisted_public_text_does_not_self_trigger_content_rules() -> None:
    """Scanning every real public text member must not make the candidate self-trigger."""
    root = Path(__file__).resolve().parents[1]
    findings: dict[str, tuple[str, ...]] = {}

    for relative in (root / "public-allowlist.txt").read_text(encoding="utf-8").splitlines():
        path = root / relative
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        rule_ids = tuple(
            rule_id
            for rule_id in _content_rule_ids(data, relative)
            if rule_id.startswith("RG-CONTENT-")
        )
        if rule_ids:
            findings[relative] = rule_ids

    assert findings == {}


def test_license_url_exception_is_exact_root_hash_bound() -> None:
    """A broad URL exception must not permit Apache text in another path or a modified LICENSE."""
    license_bytes = (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes()

    assert _content_rule_ids(license_bytes, "LICENSE") == ()
    assert "RG-CONTENT-URL" in _content_rule_ids(license_bytes, "NOTICE")
    assert "RG-CONTENT-URL" in _content_rule_ids(license_bytes + b"\n", "LICENSE")


@pytest.mark.parametrize(
    ("shape", "rule"),
    [
        ("phone", "RG-CONTENT-PII"),
        ("identity", "RG-CONTENT-PII"),
        ("home", "RG-CONTENT-ABSOLUTE"),
        ("drive", "RG-CONTENT-ABSOLUTE"),
        ("unc", "RG-CONTENT-ABSOLUTE"),
        ("endpoint-field", "RG-CONTENT-PROVIDER"),
    ],
)
def test_realistic_pii_path_and_provider_variants_are_blocked(
    tmp_path: Path, shape: str, rule: str
) -> None:
    """Dropping a realistic structured variant must leave a common leak shape undetected."""
    payloads = {
        "phone": "+86 " + "138" + "0013" + "8000",
        "identity": "110" + "105" + "1990" + "0101" + "123" + "X",
        "home": "/" + "home/synthetic/work",
        "drive": "C:" + r"\Users\synthetic\work",
        "unc": "\\\\" + r"server\share\work",
        "endpoint-field": "endpoint" + ": synthetic-service",
    }
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / "notes.txt", payloads[shape])
    _append_allowlist(allowlist, "notes.txt")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert rule in result.rule_ids


@pytest.mark.parametrize(
    ("attack", "expected_rule"),
    [
        ("alphabetic-secret", "RG-CONTENT-SECRET"),
        ("single-digit-position", "RG-CONTENT-FINANCIAL"),
        ("generic-holding", "RG-CONTENT-FINANCIAL"),
    ],
)
def test_structured_fields_block_without_value_shape_assumptions(
    tmp_path: Path, attack: str, expected_rule: str
) -> None:
    """Constraining configured values by length or digits must let structured leaks pass."""
    payloads = (
        ("alphabetic-secret", "api_" + "key = syntheticalphabeticvalue"),
        ("single-digit-position", "position_" + "size: " + "5"),
        ("generic-holding", "holding" + ": AAPL"),
    )
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / "notes.txt", dict(payloads)[attack])
    _append_allowlist(allowlist, "notes.txt")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert expected_rule in result.rule_ids


def test_content_scanning_remains_fail_closed_for_size_nul_and_utf8(tmp_path: Path) -> None:
    """Removing byte-level guards must let oversized or undecodable members bypass scanning."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    (root / "oversized.txt").write_bytes(b"x" * 2_000_001)
    (root / "nul.txt").write_bytes(b"synthetic\x00payload")
    (root / "invalid.txt").write_bytes(b"synthetic\xffpayload")
    _append_allowlist(allowlist, "invalid.txt", "nul.txt", "oversized.txt")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-CONTENT-LIMIT", "RG-SOURCE-BINARY"} <= set(result.rule_ids)


def test_register_and_sbom_url_handling_is_structural_not_a_global_bypass(
    tmp_path: Path,
) -> None:
    """Exempting whole structured files must allow unrelated endpoints in approved metadata."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    register_payload = json.loads(register.read_text(encoding="utf-8"))
    register_payload["documentation_url"] = "https" + "://example.invalid/register-extra"
    _write(register, json.dumps(register_payload))

    register_result = audit_release(
        root, allowlist=allowlist, dependency_register=register, sbom=sbom
    )

    del register_payload["documentation_url"]
    _write(register, json.dumps(register_payload))
    sbom_payload = json.loads(sbom.read_text(encoding="utf-8"))
    sbom_payload["documentation_url"] = "https" + "://example.invalid/sbom-extra"
    _write(sbom, json.dumps(sbom_payload))
    sbom_result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-CONTENT-URL" in register_result.rule_ids
    assert "RG-CONTENT-URL" in sbom_result.rule_ids


def test_dependency_register_rejects_an_unreviewed_source_url(tmp_path: Path) -> None:
    """A URL-shaped value must not bypass the exact package/version source binding."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    payload = json.loads(register.read_text(encoding="utf-8"))
    payload["dependencies"][0]["source_url"] = "https" + "://example.invalid/sample-dep"
    _write(register, json.dumps(payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-DEPENDENCY-REGISTER" in result.rule_ids


def test_json_escaped_unapproved_url_still_blocks(tmp_path: Path) -> None:
    """Scanning only raw URL spelling must let JSON slash escaping hide an endpoint."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    escaped_url = "https" + r":\/\/example.invalid/api"
    _write(root / "notes.json", '{"url":"' + escaped_url + '"}')
    _append_allowlist(allowlist, "notes.json")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-CONTENT-URL" in result.rule_ids


def test_control_character_member_name_is_never_rendered(tmp_path: Path) -> None:
    """Accepting control characters in safe paths must permit line injection in human output."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    injected_line = "PUBLIC_" + "RELEASE_READY"
    _write(root / ("unsafe\n" + injected_line), "synthetic\n")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert injected_line not in result.to_human()
    assert "RG-SOURCE-PATH" in result.rule_ids


def test_clean_commit_identity_is_not_content_pii_but_message_leaks_still_block(
    tmp_path: Path,
) -> None:
    """Scanning identity headers as message content must reject every normal Git commit."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    identity_email = "sourcequorum-phase-a" + "@users.invalid"
    _commit_all(root, email=identity_email)

    clean = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    message = _leak_payload("RG-CONTENT-SECRET")
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            f"user.email={identity_email}",
            "commit",
            "--allow-empty",
            "-qm",
            message,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    leaked = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-CONTENT" not in clean.rule_ids
    assert "RG-GIT-CONTENT" in leaked.rule_ids
    assert "SYNTHETIC_123456789" not in leaked.to_json()


def test_git_identity_exemption_requires_exact_pii_classification() -> None:
    """Treating no findings as PII must not hide a non-PII localhost identity."""

    def commit_with_email(email: str) -> bytes:
        return (
            b"tree "
            + b"0" * 40
            + b"\nauthor synthetic <"
            + email.encode()
            + b"> 0 +0000\ncommitter synthetic <name"
            + b"@example.invalid> 0 +0000\n\nsynthetic\n"
        )

    non_pii_email = "synthetic" + "@localhost"
    ordinary_email = "name" + "@example.invalid"
    non_pii = _git_object_scannable_content(commit_with_email(non_pii_email), b"commit")
    ordinary = _git_object_scannable_content(commit_with_email(ordinary_email), b"commit")

    assert non_pii is not None
    assert ordinary is not None
    assert non_pii_email.encode() in non_pii
    assert ordinary_email.encode() not in ordinary


@pytest.mark.parametrize(
    ("object_type", "payload_kind"),
    [
        ("commit", "credential"),
        ("tag", "credential"),
        ("commit", "absolute"),
        ("tag", "absolute"),
    ],
)
def test_git_identity_email_masks_only_ordinary_pii(
    tmp_path: Path, object_type: str, payload_kind: str
) -> None:
    """Masking every email-shaped identity must hide structured content in its local-part."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    ordinary_email = "sourcequorum-phase-a" + "@users.invalid"
    _commit_all(root, email=ordinary_email)
    commit_id = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True
    ).stdout.strip()
    tree_id = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, check=True, capture_output=True
    ).stdout.strip()

    def write_identity_object(email: str, label: str) -> None:
        if object_type == "commit":
            content = (
                b"tree "
                + tree_id
                + b"\nauthor synthetic <"
                + email.encode()
                + b"> 0 +0000\ncommitter synthetic <"
                + ordinary_email.encode()
                + b"> 0 +0000\n\nsynthetic\n"
            )
            object_id = _write_git_object(root, "commit", content)
            reference = f"refs/heads/identity-{label}"
        else:
            content = (
                b"object "
                + commit_id
                + b"\ntype commit\ntag identity-"
                + label.encode()
                + b"\ntagger synthetic <"
                + email.encode()
                + b"> 0 +0000\n\nsynthetic\n"
            )
            object_id = _write_git_object(root, "tag", content)
            reference = f"refs/tags/identity-{label}"
        subprocess.run(
            ["git", "update-ref", reference, object_id],
            cwd=root,
            check=True,
            capture_output=True,
        )

    write_identity_object(ordinary_email, "ordinary")
    ordinary = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)
    unsafe_email = (
        "api_" + "key=SQ_IDENTITY_" + object_type.upper() + "_123456789" + "@example.invalid"
        if payload_kind == "credential"
        else "/Users/" + "synthetic/work" + "@users"
    )
    write_identity_object(unsafe_email, payload_kind)
    attacked = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)
    unsafe_marker = "SQ_IDENTITY_" if payload_kind == "credential" else "/Users/" + "synthetic"

    assert "RG-GIT-CONTENT" not in ordinary.rule_ids
    assert "RG-GIT-CONTENT" in attacked.rule_ids
    assert unsafe_marker not in attacked.to_json()


@pytest.mark.parametrize("attack", ["author-secret", "continuation-url", "identity-email-secret"])
def test_git_commit_header_leak_is_content_while_identity_email_is_masked(
    tmp_path: Path, attack: str
) -> None:
    """Discarding the whole commit header must hide names and continuation payloads."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _commit_all(root)
    tree_id = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.strip()
    identity_email = (
        "api_" + "key=SQ_IDENTITY_EMAIL_123456789"
        if attack == "identity-email-secret"
        else "synthetic.person" + "@example.invalid"
    )
    author_name = "api_" + "key=SQ_HEADER_123456789" if attack == "author-secret" else "synthetic"
    continuation = (
        b"gpgsig synthetic\n " + ("https" + "://example.invalid/header").encode() + b"\n"
        if attack == "continuation-url"
        else b""
    )
    commit_content = (
        b"tree "
        + tree_id
        + b"\nauthor "
        + author_name.encode()
        + b" <"
        + identity_email.encode()
        + b"> 0 +0000\ncommitter synthetic <"
        + identity_email.encode()
        + b"> 0 +0000\n"
        + continuation
        + b"\nsynthetic\n"
    )
    commit_id = _write_git_object(root, "commit", commit_content)
    subprocess.run(
        ["git", "update-ref", f"refs/heads/{attack}", commit_id],
        cwd=root,
        check=True,
        capture_output=True,
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-CONTENT" in result.rule_ids
    assert "SQ_HEADER_123456789" not in result.to_json()


def test_git_tag_header_leak_is_content(tmp_path: Path) -> None:
    """Scanning only an annotated tag message must let its structured tag name carry a secret."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _commit_all(root)
    commit_id = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True
    ).stdout.strip()
    identity_email = "synthetic.person" + "@example.invalid"
    tag_name = "api_" + "key=SQ_TAG_HEADER_123456789"
    tag_content = (
        b"object "
        + commit_id
        + b"\ntype commit\ntag "
        + tag_name.encode()
        + b"\ntagger synthetic <"
        + identity_email.encode()
        + b"> 0 +0000\n\nsynthetic\n"
    )
    tag_id = _write_git_object(root, "tag", tag_content)
    subprocess.run(
        ["git", "update-ref", "refs/tags/header-leak", tag_id],
        cwd=root,
        check=True,
        capture_output=True,
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-CONTENT" in result.rule_ids
    assert "SQ_TAG_HEADER_123456789" not in result.to_human()


def test_reachable_blob_outside_commit_trees_is_scanned_fail_closed(tmp_path: Path) -> None:
    """Scanning blobs only through commit trees must miss a blob referenced directly by a tag."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _commit_all(root)
    credential = "api_" + "key=SQ_DIRECT_BLOB_123456789"
    blob_id = _write_git_object(root, "blob", credential.encode())
    subprocess.run(
        ["git", "update-ref", "refs/tags/blob-only", blob_id],
        cwd=root,
        check=True,
        capture_output=True,
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-CONTENT-SECRET" in result.rule_ids
    assert "RG-GIT-CONTENT" not in result.rule_ids
    assert "SQ_DIRECT_BLOB_123456789" not in result.to_json()


def test_git_tree_uses_the_same_exact_hidden_policy_as_the_source_tree(tmp_path: Path) -> None:
    """Maintaining a second Git dot-name policy must reject public names or admit covert ones."""
    cases = (
        (".gitignore", False),
        (".github/workflows/ci.yml", False),
        (".github", True),
        (".covert", True),
        (".github/.covert", True),
    )
    for index, (path, blocked) in enumerate(cases):
        root, allowlist, register, sbom = _approved_tree(tmp_path / str(index))
        _write(root / path, "synthetic\n")
        _append_allowlist(allowlist, path)
        _commit_all(root)

        result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

        assert ("RG-GIT-NAME" in result.rule_ids) is blocked


def _schema_carrier_result(tmp_path: Path, carrier: str, content: str) -> AuditResult:
    root, allowlist, register, sbom = _approved_tree(tmp_path, "sourcequorum")
    logical_path = "src/sourcequorum/_schemas/example.schema.json"
    _write(root / logical_path, "{}")
    _append_allowlist(allowlist, logical_path)
    artifacts: tuple[Path, ...] = ()
    if carrier == "source":
        _write(root / logical_path, content)
    elif carrier == "git":
        _write(root / logical_path, content)
        _commit_all(root)
        (root / logical_path).unlink()
    elif carrier == "wheel":
        artifacts = (
            _wheel_with_member(
                tmp_path,
                "sourcequorum",
                "sourcequorum/_schemas/example.schema.json",
                content,
                "schema",
            ),
        )
    else:
        artifacts = (_sdist_with_member(tmp_path, "sourcequorum", logical_path, content, "schema"),)
    return audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=artifacts,
    )


def test_schema_url_is_allowed_in_source_git_wheel_and_sdist(tmp_path: Path) -> None:
    """Losing logical paths in any carrier must reject the exact packaged schema declaration."""
    schema_url = "https" + "://json-schema.org/draft/2020-12/schema"
    allowed = json.dumps({"$schema": schema_url, "type": "object"})
    blocked = json.dumps(
        {"$schema": schema_url, "description": "https" + "://example.invalid/extra"}
    )

    for carrier in ("source", "git", "wheel", "sdist"):
        allowed_result = _schema_carrier_result(tmp_path / f"allowed-{carrier}", carrier, allowed)
        blocked_result = _schema_carrier_result(tmp_path / f"blocked-{carrier}", carrier, blocked)

        assert "RG-CONTENT-URL" not in allowed_result.rule_ids
        assert "RG-GIT-CONTENT" not in allowed_result.rule_ids
        assert "RG-CONTENT-URL" in blocked_result.rule_ids


def test_duplicate_schema_keys_cannot_hide_a_url_in_any_carrier(tmp_path: Path) -> None:
    """Keeping only the last JSON key must let an earlier endpoint evade schema URL checks."""
    schema_url = "https" + "://json-schema.org/draft/2020-12/schema"
    hidden_url = "https" + "://example.invalid/hidden"
    duplicate_schema = (
        '{"$schema":'
        + json.dumps(hidden_url)
        + ',"$schema":'
        + json.dumps(schema_url)
        + ',"type":"object"}'
    )

    for carrier in ("source", "git", "wheel", "sdist"):
        result = _schema_carrier_result(tmp_path / carrier, carrier, duplicate_schema)

        assert "RG-CONTENT-URL" in result.rule_ids


def test_duplicate_register_key_is_rejected_before_last_value_wins(tmp_path: Path) -> None:
    """Last-key-wins parsing must hide an unreviewed source URL in an approved register."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    payload = json.loads(register.read_text(encoding="utf-8"))
    approved_url = payload["dependencies"][0]["source_url"]
    hidden_url = "https" + "://example.invalid/hidden-register"
    source_key = json.dumps("source_url")
    approved_field = source_key + ": " + json.dumps(approved_url)
    duplicate_field = source_key + ": " + json.dumps(hidden_url) + ", " + approved_field
    _write(register, register.read_text(encoding="utf-8").replace(approved_field, duplicate_field))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-CONTENT-URL" in result.rule_ids
    assert "RG-DEPENDENCY-REGISTER" in result.rule_ids


def _leak_carrier_result(tmp_path: Path, carrier: str, content: str) -> AuditResult:
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    logical_path = "src/samplepkg/leak.txt"
    _write(root / logical_path, "synthetic\n")
    _append_allowlist(allowlist, logical_path)
    artifacts: tuple[Path, ...] = ()
    if carrier == "source":
        _write(root / logical_path, content)
    elif carrier == "git":
        _write(root / logical_path, content)
        _commit_all(root)
        (root / logical_path).unlink()
    elif carrier == "wheel":
        artifacts = (
            _wheel_with_member(tmp_path, "samplepkg", "samplepkg/leak.txt", content, "leak"),
        )
    else:
        artifacts = (_sdist_with_member(tmp_path, "samplepkg", logical_path, content, "leak"),)
    return audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=artifacts,
    )


@pytest.mark.parametrize(
    "rule",
    [
        "RG-CONTENT-SECRET",
        "RG-CONTENT-ABSOLUTE",
        "RG-CONTENT-PII",
        "RG-CONTENT-URL",
    ],
)
def test_each_real_leak_shape_still_fails_in_source_git_and_artifact(
    tmp_path: Path, rule: str
) -> None:
    """Carrier-specific classifiers must not silently drop a real structured leak."""
    content = _leak_payload(rule)

    for carrier in ("source", "git", "wheel", "sdist"):
        result = _leak_carrier_result(tmp_path / carrier, carrier, content)

        assert rule in result.rule_ids
        if carrier == "git":
            assert "RG-GIT-CONTENT" not in result.rule_ids


def test_pending_rights_is_a_fixed_release_blocker(tmp_path: Path) -> None:
    """Changing a pending rights register to success must not permit public release."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(register, json.dumps({"status": "pending", "dependencies": []}))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert result.public_release_ready is False
    assert result.rule_ids == ("RG-RIGHTS-PENDING",)
    assert result.exit_code == 1


def test_unknown_and_missing_allowlist_members_block_release(tmp_path: Path) -> None:
    """Dropping a source member or inventing an allowlist member must fail reconciliation."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(allowlist, "pyproject.toml\nmissing.txt\n")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-ALLOWLIST-MISSING" in result.rule_ids
    assert "RG-ALLOWLIST-UNKNOWN" in result.rule_ids
    assert result.exit_code == 1


def test_source_links_binary_and_archives_are_rejected(tmp_path: Path) -> None:
    """Removing type checks must allow unsafe filesystem payloads into a release candidate."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / "payload.bin", "\x00")
    _write(root / "archive.zip", "not a real archive")
    (root / "linked.txt").symlink_to("pyproject.toml")
    _write(
        allowlist,
        allowlist.read_text(encoding="utf-8") + "archive.zip\nlinked.txt\npayload.bin\n",
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SOURCE-BINARY", "RG-SOURCE-ARCHIVE", "RG-SOURCE-SYMLINK"} <= set(result.rule_ids)


def test_hardlinks_and_fifos_are_rejected(tmp_path: Path) -> None:
    """Removing special-file checks must let a linked or FIFO source member pass."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    os.link(root / "pyproject.toml", root / "linked-copy.txt")
    os.mkfifo(root / "stream")
    _write(
        allowlist,
        allowlist.read_text(encoding="utf-8") + "linked-copy.txt\nstream\n",
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SOURCE-HARDLINK", "RG-SOURCE-SPECIAL"} <= set(result.rule_ids)


def test_git_remote_and_reachable_unsafe_object_block_without_echoing_data(tmp_path: Path) -> None:
    """Removing Git inspection must allow a local remote or unsafe committed text to pass."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / "history.txt", "token=" + "SQ_SENTINEL_GIT_OBJECT_123")
    _append_allowlist(allowlist, "history.txt")
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=review@invalid",
            "commit",
            "-qm",
            "synthetic",
        ],
        [
            "git",
            "remote",
            "add",
            "origin",
            "https" + "://SQ_SENTINEL_REMOTE.invalid/repo",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-GIT-REMOTE", "RG-CONTENT-SECRET"} <= set(result.rule_ids)
    assert "SQ_SENTINEL" not in result.to_human()


def test_incomplete_dependency_register_blocks_release(tmp_path: Path) -> None:
    """Removing dependency-license coverage checks must permit an incomplete SBOM register."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(
        register,
        json.dumps(
            {
                "status": "approved",
                "rights_status": "approved",
                "sbom_complete": False,
                "dependencies": [{"package": "samplepkg"}],
            }
        ),
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-DEPENDENCY-REGISTER" in result.rule_ids


@pytest.mark.parametrize(
    "mutation",
    ["empty", "duplicate", "pending", "conditional", "extra", "version", "spdx"],
)
def test_dependency_register_must_exactly_reconcile_project_and_sbom(
    tmp_path: Path, mutation: str
) -> None:
    """Weakening exact dependency reconciliation must let a dishonest register pass."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    payload = json.loads(register.read_text(encoding="utf-8"))
    dependency = payload["dependencies"][0]
    if mutation == "empty":
        payload["dependencies"] = []
    elif mutation == "duplicate":
        payload["dependencies"].append(dict(dependency))
    elif mutation == "pending":
        dependency["status"] = "pending"
    elif mutation == "conditional":
        dependency["notice"] = "conditional"
    elif mutation == "extra":
        extra = dict(dependency)
        extra["package"] = "undeclared-dep"
        payload["dependencies"].append(extra)
    elif mutation == "version":
        dependency["version"] = "9.9.9"
    else:
        dependency["spdx"] = "UNKNOWN"
    _write(register, json.dumps(payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-DEPENDENCY-REGISTER" in result.rule_ids


@pytest.mark.parametrize("mutation", ("register-name", "component-purl"))
def test_register_and_sbom_component_identities_match_exactly(
    tmp_path: Path, mutation: str
) -> None:
    """Canonical-name equivalence must not hide a changed factual component identity or purl."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    if mutation == "register-name":
        payload = json.loads(register.read_text(encoding="utf-8"))
        payload["dependencies"][0]["package"] = "sample_dep"
        payload["dependencies"][0]["source_url"] = "https" + "://pypi.org/project/sample_dep/1.2.3/"
        _write(register, json.dumps(payload))
    else:
        payload = json.loads(sbom.read_text(encoding="utf-8"))
        payload["components"][0]["purl"] = "pkg:pypi/another-dep@1.2.3"
        _write(sbom, json.dumps(payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SBOM", "RG-DEPENDENCY-REGISTER"} & set(result.rule_ids)


@pytest.mark.parametrize(
    ("carrier", "mutation"),
    [
        ("register", "profile"),
        ("register", "scope"),
        ("sbom", "profile"),
        ("sbom", "scope"),
        ("sbom", "root-license"),
        ("sbom", "root-edge"),
    ],
)
def test_reference_runtime_scope_root_and_root_edge_are_fixed(
    tmp_path: Path, carrier: str, mutation: str
) -> None:
    """Relaxing the fixed profile graph must let an incomplete reference runtime look complete."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    target = register if carrier == "register" else sbom
    payload = json.loads(target.read_text(encoding="utf-8"))
    if carrier == "register":
        field = "profile" if mutation == "profile" else "completeness_scope"
        payload[field] = "all-platforms"
    elif mutation in {"profile", "scope"}:
        property_name = (
            "sourcequorum:runtime-profile"
            if mutation == "profile"
            else "sourcequorum:completeness-scope"
        )
        property_entry = next(
            item for item in payload["metadata"]["properties"] if item["name"] == property_name
        )
        property_entry["value"] = "all-platforms"
    elif mutation == "root-license":
        payload["metadata"]["component"]["licenses"] = [{"expression": "MIT"}]
    else:
        payload["dependencies"][0]["dependsOn"] = []
    _write(target, json.dumps(payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    expected = "RG-DEPENDENCY-REGISTER" if carrier == "register" else "RG-SBOM"
    assert expected in result.rule_ids


def test_notice_decision_is_a_closed_two_value_enum(tmp_path: Path) -> None:
    """Accepting an invented notice waiver must bypass the artifact notice review."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    payload = json.loads(register.read_text(encoding="utf-8"))
    payload["dependencies"][0]["notice"] = "waived"
    _write(register, json.dumps(payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-DEPENDENCY-REGISTER" in result.rule_ids


def test_psf_2_0_is_an_accepted_exact_spdx_identifier(tmp_path: Path) -> None:
    """Omitting PSF-2.0 from the reviewed SPDX set must reject typing-extensions."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    register_payload = json.loads(register.read_text(encoding="utf-8"))
    register_payload["dependencies"][0]["spdx"] = "PSF-2.0"
    _write(register, json.dumps(register_payload))
    sbom_payload = json.loads(sbom.read_text(encoding="utf-8"))
    sbom_payload["components"][0]["licenses"] = [{"expression": "PSF-2.0"}]
    _write(sbom, json.dumps(sbom_payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert result.rule_ids == ()


@pytest.mark.parametrize("carrier", ("wheel", "sdist"))
def test_artifact_requires_dist_must_equal_pyproject_exactly(tmp_path: Path, carrier: str) -> None:
    """Ignoring artifact dependency metadata must permit a widened packaged requirement."""
    root, allowlist, register, sbom = _approved_tree(tmp_path, project_name="samplepkg")
    wheel_requires = ("sample-dep>=1,<3",) if carrier == "wheel" else ("sample-dep>=1,<2",)
    sdist_requires = ("sample-dep>=1,<3",) if carrier == "sdist" else ("sample-dep>=1,<2",)
    wheel, sdist = _complete_artifacts(tmp_path, root, allowlist, wheel_requires, sdist_requires)

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel if carrier == "wheel" else sdist,),
    )

    assert "RG-ARTIFACT-DEPENDENCIES" in result.rule_ids


def test_artifact_requires_dist_preserves_extras_and_markers(tmp_path: Path) -> None:
    """Dropping extras or markers must let artifact metadata diverge from pyproject declarations."""
    root, allowlist, register, sbom = _approved_tree(tmp_path, project_name="samplepkg")
    pyproject = root / "pyproject.toml"
    declaration = "sample-dep[feature]>=1,<2; python_version < '3.13'"
    _write(
        pyproject,
        pyproject.read_text(encoding="utf-8").replace("sample-dep>=1,<2", declaration),
    )
    wheel, sdist = _complete_artifacts(tmp_path, root, allowlist, (declaration,), (declaration,))

    matching = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel, sdist),
    )
    wheel, _ = _complete_artifacts(
        tmp_path,
        root,
        allowlist,
        ("sample-dep[feature]>=1,<2; python_version < '3.14'",),
        (declaration,),
    )
    mismatched = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )

    assert "RG-ARTIFACT-DEPENDENCIES" not in matching.rule_ids
    assert "RG-ARTIFACT-DEPENDENCIES" in mismatched.rule_ids


@pytest.mark.parametrize(
    ("uses", "blocked"),
    [
        (f"actions/checkout@{CHECKOUT_SHA}", False),
        (f"actions/setup-python@{SETUP_PYTHON_SHA}", False),
        ("actions/checkout@v4", True),
        ("third-party/example@" + "1" * 40, True),
        ("./.github/actions/local", False),
    ],
)
def test_workflow_actions_are_full_sha_pinned_and_officially_registered(
    tmp_path: Path, uses: str, blocked: bool
) -> None:
    """Skipping action identity checks must permit mutable or unreviewed workflow code."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    workflow = ".github/workflows/ci.yml"
    _write(root / workflow, f"name: synthetic\njobs:\n  test:\n    steps:\n      - uses: {uses}\n")
    _append_allowlist(allowlist, workflow)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert ("RG-WORKFLOW-ACTION" in result.rule_ids) is blocked


@pytest.mark.parametrize(
    "uses",
    (
        f"actions/checkout@{CHECKOUT_SHA}",
        "third-party/example@" + "1" * 40,
    ),
)
def test_workflow_flow_mapping_uses_is_conservatively_rejected(tmp_path: Path, uses: str) -> None:
    """A legal YAML flow mapping must not bypass the supported block-style parser."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    workflow = ".github/workflows/ci.yml"
    _write(
        root / workflow,
        f"name: synthetic\njobs:\n  test:\n    steps:\n      - {{ uses: {uses} }}\n",
    )
    _append_allowlist(allowlist, workflow)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-WORKFLOW-ACTION" in result.rule_ids


@pytest.mark.parametrize(
    ("quote", "uses", "blocked"),
    (
        ("'", f"actions/checkout@{CHECKOUT_SHA}", False),
        ('"', f"actions/checkout@{CHECKOUT_SHA}", False),
        ('"', "actions/checkout@v4", True),
        ('"', "third-party/example@" + "1" * 40, True),
    ),
)
def test_workflow_job_level_block_uses_validates_a_quoted_identity(
    tmp_path: Path, quote: str, uses: str, blocked: bool
) -> None:
    """Supported job-level block syntax and quoted values retain exact identity checks."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    workflow = ".github/workflows/ci.yml"
    _write(
        root / workflow,
        f"name: synthetic\njobs:\n  reusable:\n    uses: {quote}{uses}{quote}\n",
    )
    _append_allowlist(allowlist, workflow)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert ("RG-WORKFLOW-ACTION" in result.rule_ids) is blocked


@pytest.mark.parametrize(
    "workflow_body",
    (
        "      - uses: >\n          actions/checkout@" + CHECKOUT_SHA + "\n",
        "      - uses: *reviewed_action\n",
    ),
)
def test_workflow_unparsed_multiline_or_alias_uses_is_rejected(
    tmp_path: Path, workflow_body: str
) -> None:
    """Unsupported multiline and alias values must fail closed without a YAML framework."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    workflow = ".github/workflows/ci.yml"
    _write(
        root / workflow,
        "name: synthetic\njobs:\n  test:\n    steps:\n" + workflow_body,
    )
    _append_allowlist(allowlist, workflow)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-WORKFLOW-ACTION" in result.rule_ids


@pytest.mark.parametrize(
    "spdx",
    [
        "TOTALLY-FAKE",
        "MIT AND TOTALLY-FAKE",
        "MIT WITH TOTALLY-FAKE-exception",
        "MIT OR",
        "(MIT AND Apache-2.0",
    ],
)
def test_matching_unknown_or_malformed_spdx_is_rejected(tmp_path: Path, spdx: str) -> None:
    """Comparing two arbitrary strings must not turn an invented SPDX value into approval."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    register_payload = json.loads(register.read_text(encoding="utf-8"))
    register_payload["dependencies"][0]["spdx"] = spdx
    _write(register, json.dumps(register_payload))
    sbom_payload = json.loads(sbom.read_text(encoding="utf-8"))
    sbom_payload["components"][0]["licenses"] = [{"expression": spdx}]
    _write(sbom, json.dumps(sbom_payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SBOM", "RG-DEPENDENCY-REGISTER"} <= set(result.rule_ids)


@pytest.mark.parametrize(
    "spdx",
    [
        "MIT ORApache-2.0",
        "MIT ANDApache-2.0",
        "MIT WITHLLVM-exception",
        "MIT Apache-2.0",
        "MIT@",
        "MIT trailing",
    ],
)
def test_spdx_lexer_requires_complete_separated_tokens(tmp_path: Path, spdx: str) -> None:
    """A find-all lexer must not silently split adjacency or discard unmatched junk."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    register_payload = json.loads(register.read_text(encoding="utf-8"))
    register_payload["dependencies"][0]["spdx"] = spdx
    _write(register, json.dumps(register_payload))
    sbom_payload = json.loads(sbom.read_text(encoding="utf-8"))
    sbom_payload["components"][0]["licenses"] = [{"expression": spdx}]
    _write(sbom, json.dumps(sbom_payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SBOM", "RG-DEPENDENCY-REGISTER"} <= set(result.rule_ids)


def test_known_compound_spdx_expression_is_accepted(tmp_path: Path) -> None:
    """Rejecting every compound expression must block a known, well-formed local license pair."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    expression = "(MIT OR Apache-2.0)"
    register_payload = json.loads(register.read_text(encoding="utf-8"))
    register_payload["dependencies"][0]["spdx"] = expression
    _write(register, json.dumps(register_payload))
    sbom_payload = json.loads(sbom.read_text(encoding="utf-8"))
    sbom_payload["components"][0]["licenses"] = [{"expression": expression}]
    _write(sbom, json.dumps(sbom_payload))

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert result.rule_ids == ()


def test_sbom_missing_duplicate_or_extra_components_blocks_release(tmp_path: Path) -> None:
    """Trusting the register alone must let malformed resolved dependency inventories pass."""
    for mutation in ("missing", "duplicate", "extra"):
        case = tmp_path / mutation
        root, allowlist, register, sbom = _approved_tree(case)
        payload = json.loads(sbom.read_text(encoding="utf-8"))
        component = payload["components"][0]
        if mutation == "missing":
            payload["components"] = []
        elif mutation == "duplicate":
            payload["components"].append(dict(component))
        else:
            payload["components"].append(
                {
                    "type": "library",
                    "name": "transitive-dep",
                    "version": "2.0.0",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                }
            )
        _write(sbom, json.dumps(payload))

        result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

        assert "RG-SBOM" in result.rule_ids


def test_unsafe_wheel_and_sdist_members_are_rejected_without_extraction(tmp_path: Path) -> None:
    """Removing archive member validation must permit traversal and private artifact files."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    wheel = tmp_path / "samplepkg-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("samplepkg/__init__.py", "")
        archive.writestr("../SQ_SENTINEL_TRAVERSAL.txt", "SQ_SENTINEL_ARCHIVE_CONTENT")
    sdist = tmp_path / "samplepkg-0.0.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        content = b"SQ_SENTINEL_PRIVATE"
        info = tarfile.TarInfo("samplepkg-0.0.1/private/notes.txt")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel, sdist),
    )

    assert {"RG-ARTIFACT-PATH", "RG-ARTIFACT-PRIVATE"} <= set(result.rule_ids)
    assert "SQ_SENTINEL" not in result.to_json()


def test_empty_wheel_reports_every_missing_expected_member(tmp_path: Path) -> None:
    """Checking only unexpected members must allow an empty wheel to pass artifact exactness."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    wheel = tmp_path / "samplepkg-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w"):
        pass

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )

    assert "RG-ARTIFACT-MISSING" in result.rule_ids


def test_sdist_missing_privacy_document_reports_a_missing_artifact_member(tmp_path: Path) -> None:
    """Omitting the local privacy boundary from an sdist must block the artifact."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    sdist = tmp_path / "samplepkg-0.0.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in {
            "PKG-INFO": b"",
            "public-allowlist.txt": allowlist.read_bytes(),
            "pyproject.toml": (root / "pyproject.toml").read_bytes(),
            "src/samplepkg/__init__.py": (root / "src" / "samplepkg" / "__init__.py").read_bytes(),
        }.items():
            info = tarfile.TarInfo(f"samplepkg-0.0.1/{member}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )

    assert "RG-ARTIFACT-MISSING" in result.rule_ids


@pytest.mark.parametrize(
    "alias",
    (
        "sourcequorum//__init__.py",
        "sourcequorum/./__init__.py",
    ),
)
def test_wheel_rejects_alias_only_package_member_as_path_and_missing(
    tmp_path: Path, alias: str
) -> None:
    """Normalizing raw aliases must not let them satisfy the wheel member contract."""
    root, allowlist, register, sbom = _approved_tree(tmp_path, project_name="sourcequorum")
    wheel = tmp_path / "sourcequorum-0.0.1-py3-none-any.whl"
    members = {
        "sourcequorum/__init__.py": (root / "src" / "sourcequorum" / "__init__.py").read_bytes(),
        "sourcequorum-0.0.1.dist-info/METADATA": _apache_metadata(),
        "sourcequorum-0.0.1.dist-info/RECORD": b"",
        "sourcequorum-0.0.1.dist-info/WHEEL": b"",
        "sourcequorum-0.0.1.dist-info/entry_points.txt": b"",
        "sourcequorum-0.0.1.dist-info/licenses/LICENSE": (root / "LICENSE").read_bytes(),
        "sourcequorum-0.0.1.dist-info/licenses/NOTICE": (root / "NOTICE").read_bytes(),
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)

    canonical_result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )
    assert canonical_result.rule_ids == ()

    members[alias] = members.pop("sourcequorum/__init__.py")
    with zipfile.ZipFile(wheel, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )

    assert {"RG-ARTIFACT-PATH", "RG-ARTIFACT-MISSING"} <= set(result.rule_ids)


@pytest.mark.parametrize(
    "alias",
    (
        "sourcequorum//__init__.py",
        "sourcequorum/./__init__.py",
    ),
)
def test_sdist_rejects_alias_only_package_member_as_path_and_missing(
    tmp_path: Path, alias: str
) -> None:
    """Normalizing raw aliases must not let them satisfy the sdist member contract."""
    root, allowlist, register, sbom = _approved_tree(tmp_path, project_name="sourcequorum")
    sdist = tmp_path / "sourcequorum-0.0.1.tar.gz"
    members = {
        "PKG-INFO": _apache_metadata(),
        "LICENSE": (root / "LICENSE").read_bytes(),
        "NOTICE": (root / "NOTICE").read_bytes(),
        "PRIVACY.md": (root / "PRIVACY.md").read_bytes(),
        "dependency-register.json": (root / "dependency-register.json").read_bytes(),
        "public-allowlist.txt": allowlist.read_bytes(),
        "pyproject.toml": (root / "pyproject.toml").read_bytes(),
        "sbom.cdx.json": (root / "sbom.cdx.json").read_bytes(),
        "src/sourcequorum/__init__.py": (
            root / "src" / "sourcequorum" / "__init__.py"
        ).read_bytes(),
    }
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in members.items():
            info = tarfile.TarInfo(f"sourcequorum-0.0.1/{member}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    canonical_result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )
    assert canonical_result.rule_ids == ()

    members[f"src/{alias}"] = members.pop("src/sourcequorum/__init__.py")
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in members.items():
            info = tarfile.TarInfo(f"sourcequorum-0.0.1/{member}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )

    assert {"RG-ARTIFACT-PATH", "RG-ARTIFACT-MISSING"} <= set(result.rule_ids)


def test_sdist_rejects_regular_terminal_slash_alias_as_path_and_missing(tmp_path: Path) -> None:
    """Treating a regular TAR member ending in slash as a directory must not satisfy sdist membership."""
    root, allowlist, register, sbom = _approved_tree(tmp_path, project_name="sourcequorum")
    sdist = tmp_path / "sourcequorum-0.0.1.tar.gz"
    members = {
        "PKG-INFO": _apache_metadata(),
        "LICENSE": (root / "LICENSE").read_bytes(),
        "NOTICE": (root / "NOTICE").read_bytes(),
        "PRIVACY.md": (root / "PRIVACY.md").read_bytes(),
        "dependency-register.json": (root / "dependency-register.json").read_bytes(),
        "public-allowlist.txt": allowlist.read_bytes(),
        "pyproject.toml": (root / "pyproject.toml").read_bytes(),
        "sbom.cdx.json": (root / "sbom.cdx.json").read_bytes(),
        "src/sourcequorum/__init__.py": (
            root / "src" / "sourcequorum" / "__init__.py"
        ).read_bytes(),
    }
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in members.items():
            info = tarfile.TarInfo(f"sourcequorum-0.0.1/{member}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    canonical_result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )
    assert canonical_result.rule_ids == ()

    members["src/sourcequorum/__init__.py/"] = members.pop("src/sourcequorum/__init__.py")
    with tarfile.open(sdist, "w:gz") as archive:
        for member, content in members.items():
            info = tarfile.TarInfo(f"sourcequorum-0.0.1/{member}")
            assert info.isfile()
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )

    assert {"RG-ARTIFACT-PATH", "RG-ARTIFACT-MISSING"} <= set(result.rule_ids)


def test_wheel_rejects_duplicate_symlink_and_executable_members(tmp_path: Path) -> None:
    """Ignoring ZIP metadata must allow links, duplicates, and executable payloads."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    wheel = tmp_path / "samplepkg-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("samplepkg/__init__.py", "")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("samplepkg/__init__.py", "")
        symlink = zipfile.ZipInfo("samplepkg/link.py")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(symlink, "SQ_SENTINEL_LINK_TARGET")
        executable = zipfile.ZipInfo("samplepkg/run.py")
        executable.create_system = 3
        executable.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(executable, "")

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )

    assert {"RG-ARTIFACT-DUPLICATE", "RG-ARTIFACT-SYMLINK", "RG-ARTIFACT-EXECUTABLE"} <= set(
        result.rule_ids
    )
    assert "SQ_SENTINEL" not in result.to_json()


def test_wheel_directory_symlink_is_rejected_before_directory_skip(tmp_path: Path) -> None:
    """Skipping names ending in slash first must let a directory symlink bypass ZIP checks."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    wheel = tmp_path / "samplepkg-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        covert = zipfile.ZipInfo("covert/")
        covert.create_system = 3
        covert.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(covert, "SQ_SENTINEL_DIRECTORY_LINK")

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(wheel,),
    )

    assert "RG-ARTIFACT-SYMLINK" in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()


def test_tar_rejects_backslash_hardlink_and_fifo_before_reading(tmp_path: Path) -> None:
    """Treating non-files generically must miss dangerous tar member representations."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    sdist = tmp_path / "samplepkg-0.0.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        regular = tarfile.TarInfo("samplepkg-0.0.1\\escape.txt")
        regular.size = 0
        archive.addfile(regular, io.BytesIO())
        hardlink = tarfile.TarInfo("samplepkg-0.0.1/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "SQ_SENTINEL_LINK_TARGET"
        archive.addfile(hardlink)
        fifo = tarfile.TarInfo("samplepkg-0.0.1/fifo")
        fifo.type = tarfile.FIFOTYPE
        archive.addfile(fifo)

    result = audit_release(
        root,
        allowlist=allowlist,
        dependency_register=register,
        sbom=sbom,
        artifacts=(sdist,),
    )

    assert {"RG-ARTIFACT-PATH", "RG-ARTIFACT-HARDLINK", "RG-ARTIFACT-SPECIAL"} <= set(
        result.rule_ids
    )
    assert "SQ_SENTINEL" not in result.to_json()


def test_hidden_directory_and_directory_symlink_are_rejected(tmp_path: Path) -> None:
    """Following directory links or skipping hidden directories must bypass source traversal."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / ".hidden" / "note.txt", "synthetic")
    (root / "linked-directory").symlink_to(root / "src", target_is_directory=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-SOURCE-HIDDEN", "RG-SOURCE-SYMLINK"} <= set(result.rule_ids)


def test_allowlisted_hidden_source_still_blocks_except_frozen_github_path(tmp_path: Path) -> None:
    """Using allowlist membership as a dot-path exemption must allow covert source files."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / ".covert" / "note.txt", "synthetic")
    _write(root / ".github" / "workflows" / "ci.yml", "name: synthetic\n")
    _write(
        allowlist,
        ".covert/note.txt\n.github/workflows/ci.yml\n" + allowlist.read_text(encoding="utf-8"),
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-SOURCE-HIDDEN" in result.rule_ids
    assert not any(
        issue.rule_id == "RG-SOURCE-HIDDEN" and issue.path.startswith(".github/")
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("payload_name", "rule"),
    [
        ("private-key", "RG-CONTENT-PRIVATE-KEY"),
        ("financial", "RG-CONTENT-FINANCIAL"),
        ("provider", "RG-CONTENT-PROVIDER"),
        ("bearer", "RG-CONTENT-SECRET"),
    ],
)
def test_extended_content_rules_and_tail_scanning(
    tmp_path: Path, payload_name: str, rule: str
) -> None:
    """Scanning only the prefix or narrow secret vocabulary must miss unsafe tail content."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    payload = (
        "Authorization" + ": Bearer " + "SQ_SYNTHETIC_AUTH_123"
        if payload_name == "bearer"
        else _leak_payload(rule)
    )
    _write(root / "notes.txt", ("x" * 1_500_000) + "\n" + payload)
    _append_allowlist(allowlist, "notes.txt")

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert rule in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()


def test_git_private_member_and_ref_names_are_blocked_safely(tmp_path: Path) -> None:
    """Scanning Git text without classifying names must permit hidden history and refs."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(root / ".hidden" / ("token=" + "SQ_SENTINEL_HISTORY_123.txt"), "synthetic")
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "synthetic",
        ],
        ["git", "branch", "private/SQ_SENTINEL_REF"],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-NAME" in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()


def test_git_submodule_configuration_is_blocked(tmp_path: Path) -> None:
    """Checking only an unstaged worktree file must miss a committed submodule declaration."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    _write(
        root / ".gitmodules",
        '[submodule "synthetic"]\n\tpath = synthetic\n\turl = ../SQ_SENTINEL_SUBMODULE\n',
    )
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "synthetic",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-SUBMODULE" in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()


def test_historical_gitlink_without_gitmodules_is_blocked(tmp_path: Path) -> None:
    """Looking only for .gitmodules must miss a gitlink that exists only in reachable history."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "base",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)
    commit_id = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{commit_id},vendor/SQ_SENTINEL_GITLINK",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "gitlink",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "rm", "--cached", "vendor/SQ_SENTINEL_GITLINK"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "remove",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "reflog", "expire", "--expire=now", "--all"],
        cwd=root,
        check=True,
        capture_output=True,
    )

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-SUBMODULE" in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()
    assert commit_id not in result.to_json()


def test_git_reflog_or_unreachable_object_is_a_blocker(tmp_path: Path) -> None:
    """Ignoring reflogs and unreachable objects must permit removed unsafe history."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "first",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)
    _write(root / "orphan.txt", "token=" + "SQ_SENTINEL_ORPHAN")
    subprocess.run(["git", "add", "orphan.txt"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "second",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "reset", "--hard", "HEAD^"], cwd=root, check=True, capture_output=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert {"RG-GIT-UNREACHABLE", "RG-GIT-REFLOG"} & set(result.rule_ids)
    assert "SQ_SENTINEL" not in result.to_json()


def test_git_tag_metadata_content_is_blocked_without_echoing_it(tmp_path: Path) -> None:
    """Auditing only blobs and commits must miss unsafe annotated-tag metadata."""
    root, allowlist, register, sbom = _approved_tree(tmp_path)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "commit",
            "-qm",
            "synthetic",
        ],
        [
            "git",
            "-c",
            "user.name=synthetic",
            "-c",
            "user.email=synthetic@invalid",
            "tag",
            "-am",
            "token=" + "SQ_SENTINEL_TAG_METADATA_123",
            "v0.0.1",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)

    result = audit_release(root, allowlist=allowlist, dependency_register=register, sbom=sbom)

    assert "RG-GIT-CONTENT" in result.rule_ids
    assert "SQ_SENTINEL" not in result.to_json()
