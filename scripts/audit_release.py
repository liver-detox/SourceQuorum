"""Deterministic, local, fail-closed release-audit gate."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tomllib
from typing import Callable, cast, Sequence
import zipfile

from packaging.requirements import InvalidRequirement, Requirement


_ARCHIVE_SUFFIXES = (".zip", ".whl", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz")
_TEXT_LIMIT = 2_000_000
_HTTP_PREFIX = "http" + "://"
_HTTPS_PREFIX = "https" + "://"
_SCHEMA_URL = _HTTPS_PREFIX + "json-schema.org/draft/2020-12/schema"
_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ssh)://[^\s\"'<>]+")
_CONTENT_RULES: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "RG-CONTENT-PRIVATE-KEY",
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),),
    ),
    (
        "RG-CONTENT-SECRET",
        (
            re.compile(
                r"(?i)(?:[\"'])?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|"
                r"secret|password|cookie|authorization)\b(?:[\"'])?\s*[:=]\s*"
                r"(?:[\"'])?[^\s\"'#,;]+"
            ),
            re.compile(r"(?i)\bbearer[ \t]+[A-Za-z0-9._~+/=-]{8,}"),
        ),
    ),
    (
        "RG-CONTENT-PII",
        (
            re.compile(
                r"(?i)\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+"
                r"(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}\b"
            ),
            re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"),
            re.compile(
                r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
                r"(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)"
            ),
        ),
    ),
    (
        "RG-CONTENT-ABSOLUTE",
        (
            re.compile(r"(?:^|[\s\"'=(])/(?:Users|home)/[^\s\"'<>]+", re.MULTILINE),
            re.compile(r"(?i)(?:^|[\s\"'=(])[A-Z]:\\[^\s\"'<>]+", re.MULTILINE),
            re.compile(r"(?:^|[\s\"'=(])\\\\[^\s\\\"'<>]+\\[^\s\"'<>]+", re.MULTILINE),
        ),
    ),
    (
        "RG-CONTENT-SECURITY-ID",
        (
            re.compile(
                r"(?i)(?:[\"'])?\b(?:security[_ -]?(?:id|code)|instrument[_ -]?id)\b"
                r"(?:[\"'])?\s*[:=]\s*(?:[\"'])?\d{6}\b"
            ),
        ),
    ),
    (
        "RG-CONTENT-FINANCIAL",
        (
            re.compile(
                r"(?i)(?:[\"'])?\b(?:broker(?:[_ -]?account)?|account(?:[_ -]?(?:id|number))?|"
                r"holding(?:[_ -]?(?:symbol|quantity))?|position(?:[_ -]?(?:id|size))?|"
                r"trade(?:[_ -]?(?:id|quantity))?|transaction[_ -]?id)\b(?:[\"'])?\s*[:=]"
                r"\s*(?:[\"'])?[A-Za-z0-9][A-Za-z0-9._-]*"
            ),
        ),
    ),
    (
        "RG-CONTENT-PROVIDER",
        (
            re.compile(
                r"(?i)(?:[\"'])?\b(?:provider(?:[_ -]?name)?|endpoint|base[_ -]?url|"
                r"api[_ -]?url|service[_ -]?url|domain|network)\b(?:[\"'])?\s*[:=]\s*"
                r"(?:[\"'])?[A-Za-z0-9][A-Za-z0-9._:/-]{2,}"
            ),
        ),
    ),
)
_PRIVATE_PARTS = frozenset({"private", "internal", "provenance", "artifacts", ".superpowers"})
_SDIST_ROOT_FILES = frozenset(
    {
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
        "public-allowlist.txt",
        "pyproject.toml",
        "sbom.cdx.json",
    }
)
_SDIST_DOCS = frozenset({"docs/architecture.md", "docs/manifest-v1.md", "docs/threat-model.md"})
_SPDX_LICENSES = frozenset({"Apache-2.0", "MIT", "PSF-2.0"})
_SPDX_EXCEPTIONS = frozenset({"Classpath-exception-2.0", "LLVM-exception"})
_APACHE_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
_NOTICE_BYTES = b"SourceQuorum\nCopyright 2026 liver-detox\n"
_RUNTIME_PROFILE = "cpython-3.12-reference-runtime"
_COMPLETENESS_SCOPE = "python-package-runtime-distribution-closure-only"
# Current reviewed identities; extend only after a new private official-upstream review.
_APPROVED_ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
}
_AddIssue = Callable[[str, str], None]


@dataclass(frozen=True, order=True)
class AuditIssue:
    """A safe-to-display release-audit failure."""

    rule_id: str
    path: str = ""


@dataclass(frozen=True)
class AuditResult:
    """Stable audit result that never retains unsafe content."""

    issues: tuple[AuditIssue, ...]

    @property
    def public_release_ready(self) -> bool:
        return not self.issues

    @property
    def exit_code(self) -> int:
        return 0 if self.public_release_ready else 1

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({issue.rule_id for issue in self.issues}))

    def to_json(self) -> str:
        payload = {
            "issues": [
                {"path": issue.path, "rule_id": issue.rule_id} for issue in sorted(self.issues)
            ],
            "public_release_ready": self.public_release_ready,
        }
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"

    def to_human(self) -> str:
        lines = ["PUBLIC_RELEASE_READY" if self.public_release_ready else "PUBLIC_RELEASE_BLOCKED"]
        lines.extend(
            issue.rule_id if not issue.path else f"{issue.rule_id} {issue.path}"
            for issue in sorted(self.issues)
        )
        return "\n".join(lines) + "\n"


def _safe_relative(value: str) -> str | None:
    if (
        not value
        or "\\" in value
        or any(
            ord(character) < 32 or ord(character) == 127 or character in "\u2028\u2029"
            for character in value
        )
    ):
        return None
    raw_parts = value.split("/")
    if any(part in {"", "."} for part in raw_parts):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        return None
    return path.as_posix()


def _is_private(path: str) -> bool:
    return any(part.casefold() in _PRIVATE_PARTS for part in PurePosixPath(path).parts)


def _is_forbidden_hidden(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if path == ".gitignore":
        return False
    if (
        len(parts) >= 2
        and parts[0] == ".github"
        and all(not part.startswith(".") for part in parts[1:])
    ):
        return False
    return any(part.startswith(".") for part in parts)


def _valid_spdx(expression: str) -> bool:
    token_pattern = re.compile(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*")
    tokens: list[str] = []
    offset = 0
    while offset < len(expression):
        if expression[offset].isspace():
            offset += 1
            continue
        match = token_pattern.match(expression, offset)
        if match is None:
            return False
        spdx_token = match.group(0)
        tokens.append(spdx_token)
        offset = match.end()
    if not tokens:
        return False
    index = 0

    def primary() -> bool:
        nonlocal index
        if index >= len(tokens):
            return False
        if tokens[index] == "(":
            index += 1
            if not choice() or index >= len(tokens) or tokens[index] != ")":
                return False
            index += 1
            return True
        if tokens[index] not in _SPDX_LICENSES:
            return False
        index += 1
        if index < len(tokens) and tokens[index] == "WITH":
            index += 1
            if index >= len(tokens) or tokens[index] not in _SPDX_EXCEPTIONS:
                return False
            index += 1
        return True

    def conjunction() -> bool:
        nonlocal index
        if not primary():
            return False
        while index < len(tokens) and tokens[index] == "AND":
            index += 1
            if not primary():
                return False
        return True

    def choice() -> bool:
        nonlocal index
        if not conjunction():
            return False
        while index < len(tokens) and tokens[index] == "OR":
            index += 1
            if not conjunction():
                return False
        return True

    return bool(tokens) and choice() and index == len(tokens)


def _read_allowlist(path: Path, add: _AddIssue) -> set[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        add("RG-ALLOWLIST-READ", "")
        return set()
    entries: list[str] = []
    for line in raw.splitlines():
        if not line:
            continue
        safe = _safe_relative(line)
        if safe is None or _is_private(safe):
            add("RG-ALLOWLIST-FORMAT", "")
            continue
        entries.append(safe)
    if entries != sorted(entries) or len(entries) != len(set(entries)):
        add("RG-ALLOWLIST-FORMAT", "")
    return set(entries)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_unique_json(text: str) -> object:
    return cast(object, json.loads(text, object_pairs_hook=_unique_json_object))


def _has_unapproved_url(text: str, logical_path: str) -> bool:
    if (
        logical_path == "LICENSE"
        and hashlib.sha256(text.encode("utf-8")).hexdigest() == _APACHE_LICENSE_SHA256
    ):
        return False
    path = PurePosixPath(logical_path)
    schema_document = (
        path.parent.as_posix() == "src/sourcequorum/_schemas" and path.suffix == ".json"
    )
    try:
        payload = _load_unique_json(text)
    except (json.JSONDecodeError, ValueError):
        return _URL_PATTERN.search(text.replace(r"\/", "/")) is not None

    def inspect(value: object, value_path: tuple[str | int, ...]) -> bool:
        if isinstance(value, str):
            if _URL_PATTERN.search(value) is None:
                return False
            if schema_document and value_path == ("$schema",) and value == _SCHEMA_URL:
                return False
            if (
                logical_path == "dependency-register.json"
                and len(value_path) == 3
                and value_path[0] == "dependencies"
                and isinstance(value_path[1], int)
                and value_path[2] == "source_url"
                and value.startswith((_HTTPS_PREFIX, _HTTP_PREFIX))
                and _URL_PATTERN.fullmatch(value) is not None
            ):
                return False
            return True
        if isinstance(value, dict):
            mapping = cast(dict[str, object], value)
            return any(
                _URL_PATTERN.search(key) is not None or inspect(child, (*value_path, key))
                for key, child in mapping.items()
            )
        if isinstance(value, list):
            values = cast(list[object], value)
            return any(inspect(child, (*value_path, index)) for index, child in enumerate(values))
        return False

    return inspect(payload, ())


def _content_rule_ids(data: bytes, logical_path: str) -> tuple[str, ...]:
    """Return fixed rule IDs only; never retain or render matching text."""
    if len(data) > _TEXT_LIMIT:
        return ("RG-CONTENT-LIMIT",)
    if b"\x00" in data:
        return ("RG-SOURCE-BINARY",)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ("RG-SOURCE-BINARY",)
    found = [
        rule_id
        for rule_id, patterns in _CONTENT_RULES
        if any(pattern.search(text) for pattern in patterns)
    ]
    if _has_unapproved_url(text, logical_path):
        found.append("RG-CONTENT-URL")
    return tuple(found)


def _scan_text(data: bytes, logical_path: str, display_path: str, add: _AddIssue) -> None:
    for rule_id in _content_rule_ids(data, logical_path):
        add(rule_id, display_path)


def _source_members(root: Path, expected: set[str], add: _AddIssue) -> set[str]:
    members: set[str] = set()
    tracked = _git_output(root, "ls-files", "-z") if (root / ".git").exists() else None
    tracked_paths = (
        set(tracked.decode("utf-8", "ignore").split("\0")) if tracked is not None else None
    )
    for path in sorted(root.rglob("*")):
        try:
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
        except OSError:
            add("RG-SOURCE-UNREADABLE", "")
            continue
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if tracked_paths is not None and relative not in tracked_paths:
            continue
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            add("RG-SOURCE-SYMLINK", relative)
            members.add(relative)
            continue
        if stat.S_ISDIR(mode):
            approved_directory = any(member.startswith(relative + "/") for member in expected)
            approved_github_ancestor = relative == ".github" and approved_directory
            if _is_forbidden_hidden(relative) and not approved_github_ancestor:
                add("RG-SOURCE-HIDDEN", relative)
            if not approved_directory:
                add("RG-SOURCE-DIRECTORY", relative)
            continue
        if _safe_relative(relative) is None:
            add("RG-SOURCE-PATH", "")
            continue
        members.add(relative)
        if not stat.S_ISREG(mode):
            add("RG-SOURCE-SPECIAL", relative)
            continue
        if info.st_nlink > 1:
            add("RG-SOURCE-HARDLINK", relative)
        if relative.endswith(_ARCHIVE_SUFFIXES):
            add("RG-SOURCE-ARCHIVE", relative)
        if mode & 0o111 and relative != "scripts/audit_release.py":
            add("RG-SOURCE-EXECUTABLE", relative)
        if _is_private(relative):
            add("RG-SOURCE-PRIVATE", relative)
        if _is_forbidden_hidden(relative):
            add("RG-SOURCE-HIDDEN", relative)
        try:
            _scan_text(path.read_bytes(), relative, relative, add)
        except OSError:
            add("RG-SOURCE-UNREADABLE", relative)
    return members


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _normalized_requirement(value: str) -> str | None:
    try:
        return str(Requirement(value))
    except InvalidRequirement:
        return None


def _approved_dependency_source_url(package: object, version: object, source_url: object) -> bool:
    safe_token = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
    return (
        isinstance(package, str)
        and isinstance(version, str)
        and isinstance(source_url, str)
        and safe_token.fullmatch(package) is not None
        and safe_token.fullmatch(version) is not None
        and source_url == f"{_HTTPS_PREFIX}pypi.org/project/{package}/{version}/"
    )


def _normalized_requirements(values: Sequence[str]) -> set[str] | None:
    normalized: set[str] = set()
    for value in values:
        requirement = _normalized_requirement(value)
        if requirement is None or requirement in normalized:
            return None
        normalized.add(requirement)
    return normalized


def _project_metadata_requirements(root: Path) -> set[str] | None:
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        dependencies = project.get("dependencies", [])
        optional = project.get("optional-dependencies", {})
    except (KeyError, OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, TypeError):
        return None
    if (
        not isinstance(dependencies, list)
        or any(not isinstance(value, str) for value in dependencies)
        or not isinstance(optional, dict)
    ):
        return None
    declarations = list(cast(list[str], dependencies))
    for extra, values in optional.items():
        if (
            not isinstance(extra, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", extra) is None
            or not isinstance(values, list)
            or any(not isinstance(value, str) for value in values)
        ):
            return None
        for value in cast(list[str], values):
            requirement = _normalized_requirement(value)
            if requirement is None:
                return None
            parsed = Requirement(requirement)
            base = requirement.split(";", 1)[0].strip()
            marker = f"({parsed.marker}) and " if parsed.marker is not None else ""
            declarations.append(f"{base}; {marker}extra == '{extra}'")
    return _normalized_requirements(tuple(declarations))


def _direct_dependency_names(root: Path, add: _AddIssue) -> set[str] | None:
    _, _, dependencies = _project_details(root)
    names: set[str] = set()
    for dependency in dependencies:
        normalized = _normalized_requirement(dependency)
        if normalized is None:
            add("RG-DEPENDENCY-REGISTER", "")
            return None
        names.add(_normalized_name(Requirement(normalized).name))
    return names


def _component_spdx(component: dict[str, object]) -> str | None:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return None
    spdx_values: list[str] = []
    for license_entry in licenses:
        if not isinstance(license_entry, dict):
            continue
        if isinstance(license_entry.get("expression"), str):
            spdx_values.append(license_entry["expression"])
        elif isinstance(license_entry.get("license"), dict):
            identifier = license_entry["license"].get("id")
            if isinstance(identifier, str):
                spdx_values.append(identifier)
    if len(spdx_values) != 1 or not _valid_spdx(spdx_values[0]):
        return None
    return spdx_values[0]


def _read_sbom(
    path: Path | None, root: Path, add: _AddIssue
) -> dict[str, tuple[str, str, str]] | None:
    if path is None:
        add("RG-SBOM", "")
        return None
    try:
        payload = _load_unique_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        add("RG-SBOM", "")
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("bomFormat") != "CycloneDX"
        or payload.get("specVersion") != "1.6"
        or not isinstance(payload.get("metadata"), dict)
        or not isinstance(payload.get("components"), list)
        or not isinstance(payload.get("dependencies"), list)
    ):
        add("RG-SBOM", "")
        return None
    metadata = payload["metadata"]
    root_component = metadata.get("component")
    properties = metadata.get("properties")
    project_name, project_version, _ = _project_details(root)
    if not isinstance(root_component, dict) or not isinstance(properties, list):
        add("RG-SBOM", "")
        return None
    property_values: dict[str, str] = {}
    for item in properties:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
            or item["name"] in property_values
        ):
            add("RG-SBOM", "")
            return None
        property_values[item["name"]] = item["value"]
    if property_values != {
        "sourcequorum:runtime-profile": _RUNTIME_PROFILE,
        "sourcequorum:completeness-scope": _COMPLETENESS_SCOPE,
    }:
        add("RG-SBOM", "")
        return None
    root_ref = root_component.get("bom-ref")
    root_purl = root_component.get("purl")
    if (
        root_component.get("type") != "library"
        or root_component.get("name") != project_name
        or root_component.get("version") != project_version
        or not isinstance(root_ref, str)
        or not root_ref
        or not isinstance(root_purl, str)
        or root_purl != f"pkg:pypi/{_normalized_name(project_name)}@{project_version}"
        or _component_spdx(root_component) != "Apache-2.0"
    ):
        add("RG-SBOM", "")
        return None
    resolved: dict[str, tuple[str, str, str]] = {}
    refs: dict[str, str] = {}
    for component in payload["components"]:
        if not isinstance(component, dict):
            add("RG-SBOM", "")
            return None
        name = component.get("name")
        version = component.get("version")
        bom_ref = component.get("bom-ref")
        purl = component.get("purl")
        spdx = _component_spdx(component)
        if (
            component.get("type") != "library"
            or not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(bom_ref, str)
            or not bom_ref
            or not isinstance(purl, str)
            or spdx is None
        ):
            add("RG-SBOM", "")
            return None
        normalized = _normalized_name(name)
        if (
            not normalized
            or normalized in resolved
            or bom_ref == root_ref
            or bom_ref in refs
            or not version.strip()
            or purl != f"pkg:pypi/{normalized}@{version}"
        ):
            add("RG-SBOM", "")
            return None
        resolved[normalized] = (name, version, spdx)
        refs[bom_ref] = normalized
    all_refs = {root_ref, *refs}
    adjacency: dict[str, set[str]] = {}
    for dependency in payload["dependencies"]:
        if not isinstance(dependency, dict):
            add("RG-SBOM", "")
            return None
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn")
        if (
            not isinstance(reference, str)
            or reference not in all_refs
            or reference in adjacency
            or not isinstance(depends_on, list)
            or any(not isinstance(value, str) or value not in all_refs for value in depends_on)
            or len(depends_on) != len(set(depends_on))
        ):
            add("RG-SBOM", "")
            return None
        adjacency[reference] = set(cast(list[str], depends_on))
    direct = _direct_dependency_names(root, add)
    direct_refs = {ref for ref, name in refs.items() if direct is not None and name in direct}
    if (
        set(adjacency) != all_refs
        or root_ref not in adjacency
        or direct is None
        or adjacency[root_ref] != direct_refs
        or {refs[ref] for ref in direct_refs} != direct
    ):
        add("RG-SBOM", "")
        return None
    return resolved


def _read_register(path: Path | None, root: Path, sbom_path: Path | None, add: _AddIssue) -> bool:
    if path is None:
        add("RG-RIGHTS-PENDING", "")
        return False
    try:
        payload = _load_unique_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        add("RG-RIGHTS-PENDING", "")
        add("RG-DEPENDENCY-REGISTER", "")
        return False
    rights_approved = isinstance(payload, dict) and payload.get("rights_status") == "approved"
    if not rights_approved:
        add("RG-RIGHTS-PENDING", "")
        return False
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("status") != "approved"
        or payload.get("sbom_complete") is not True
        or payload.get("profile") != _RUNTIME_PROFILE
        or payload.get("completeness_scope") != _COMPLETENESS_SCOPE
        or not isinstance(dependencies, list)
    ):
        add("RG-DEPENDENCY-REGISTER", "")
        return False
    resolved = _read_sbom(sbom_path, root, add)
    direct = _direct_dependency_names(root, add)
    registered: dict[str, tuple[str, str, str]] = {}
    for item in dependencies:
        if (
            not isinstance(item, dict)
            or any(
                not isinstance(item.get(field), str) or not item[field]
                for field in (
                    "package",
                    "version",
                    "spdx",
                    "source_url",
                    "artifact_license_review",
                    "notice",
                    "status",
                )
            )
            or item.get("status") != "approved"
            or item.get("artifact_license_review") != "approved"
            or item.get("notice") not in {"not-required", "included-in-project-notice"}
            or not _valid_spdx(str(item.get("spdx", "")))
            or not _approved_dependency_source_url(
                item.get("package"), item.get("version"), item.get("source_url")
            )
        ):
            add("RG-DEPENDENCY-REGISTER", "")
            return False
        name = _normalized_name(str(item["package"]))
        if name in registered:
            add("RG-DEPENDENCY-REGISTER", "")
            return False
        registered[name] = (
            str(item["package"]),
            str(item["version"]),
            str(item["spdx"]),
        )
    if resolved is None or direct is None:
        return False
    if set(registered) != set(resolved) or not direct <= set(resolved):
        add("RG-SBOM", "")
        add("RG-DEPENDENCY-REGISTER", "")
        return False
    if any(registered[name] != resolved[name] for name in registered):
        add("RG-DEPENDENCY-REGISTER", "")
        return False
    return True


def _audit_workflows(root: Path, add: _AddIssue) -> None:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return
    uses_line = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(.*?)\s*$")
    uses_key_token = re.compile(r"(?:^|[\s{,?\-])(?:uses|[\"']uses[\"'])\s*(?::|$)")
    for path in sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))):
        relative = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            add("RG-WORKFLOW-ACTION", relative)
            continue
        for line in lines:
            if line.lstrip().startswith("#"):
                continue
            match = uses_line.match(line)
            if match is None:
                if uses_key_token.search(line) is not None:
                    add("RG-WORKFLOW-ACTION", relative)
                continue
            value = match.group(1).split(" #", 1)[0].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            if value.startswith("./"):
                continue
            action, separator, revision = value.partition("@")
            if (
                not separator
                or not re.fullmatch(r"[0-9a-fA-F]{40}", revision)
                or _APPROVED_ACTIONS.get(action) != revision.casefold()
            ):
                add("RG-WORKFLOW-ACTION", relative)


def _git_output(root: Path, *arguments: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    return completed.stdout if completed.returncode == 0 else None


def _has_unsafe_text(data: bytes) -> bool:
    return bool(_content_rule_ids(data, ""))


def _unsafe_git_name(data: bytes) -> bool:
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    safe = _safe_relative(value)
    if safe is None:
        return True
    return _is_private(safe) or _is_forbidden_hidden(safe)


def _git_object_scannable_content(content: bytes, object_type: bytes) -> bytes | None:
    header, separator, message = content.partition(b"\n\n")
    if not separator or b"\x00" in header:
        return None
    lines = header.splitlines()
    fields = [line for line in lines if not line.startswith(b" ")]
    if object_type == b"commit":
        if not fields or not re.fullmatch(rb"tree [0-9a-f]{40,64}", fields[0]):
            return None
        allowed = (b"tree ", b"parent ", b"author ", b"committer ", b"encoding ", b"gpgsig ")
        if any(not field.startswith(allowed) for field in fields):
            return None
        if sum(field.startswith(b"author ") for field in fields) != 1:
            return None
        if sum(field.startswith(b"committer ") for field in fields) != 1:
            return None
        for field in fields:
            if field.startswith((b"tree ", b"parent ")) and not re.fullmatch(
                rb"(?:tree|parent) [0-9a-f]{40,64}", field
            ):
                return None
            if field.startswith((b"author ", b"committer ")) and not re.fullmatch(
                rb"(?:author|committer) .+ <[^<>\r\n]+> \d+ [+-]\d{4}", field
            ):
                return None
    elif object_type == b"tag":
        if len(fields) < 4:
            return None
        if not re.fullmatch(rb"object [0-9a-f]{40,64}", fields[0]):
            return None
        if not re.fullmatch(rb"type (?:blob|commit|tag|tree)", fields[1]):
            return None
        if not fields[2].startswith(b"tag ") or not re.fullmatch(
            rb"tagger .+ <[^<>\r\n]+> \d+ [+-]\d{4}", fields[3]
        ):
            return None
        if len(fields) != 4:
            return None
    else:
        return None
    scannable_lines: list[bytes] = []
    for line in lines:
        if line.startswith((b"author ", b"committer ", b"tagger ")):
            identity = re.fullmatch(
                rb"(author|committer|tagger) (.+) <([^<>\r\n]+)> (\d+ [+-]\d{4})", line
            )
            if identity is None:
                return None
            identity_email = identity.group(3)
            email_rule_ids = set(_content_rule_ids(identity_email, ""))
            if re.fullmatch(rb"[^\s<>@]+@[^\s<>@]+", identity_email) and email_rule_ids == {
                "RG-CONTENT-PII"
            }:
                scannable_lines.append(
                    identity.group(1) + b" " + identity.group(2) + b" <> " + identity.group(4)
                )
            else:
                scannable_lines.append(
                    identity.group(1)
                    + b" "
                    + identity.group(2)
                    + b" "
                    + identity_email
                    + b" "
                    + identity.group(4)
                )
        else:
            scannable_lines.append(line)
    return b"\n".join(scannable_lines) + b"\n\n" + message


def _audit_git(root: Path, add: _AddIssue) -> None:
    git_dir = root / ".git"
    if not git_dir.exists():
        return
    remotes = _git_output(root, "remote")
    if remotes is None:
        add("RG-GIT-READ", "")
        return
    if remotes.strip():
        add("RG-GIT-REMOTE", "")
    if (root / ".gitmodules").exists():
        add("RG-GIT-SUBMODULE", ".gitmodules")
    references = _git_output(root, "for-each-ref", "--format=%(refname)")
    objects = _git_output(root, "rev-list", "--objects", "--all")
    if references is None or objects is None:
        add("RG-GIT-READ", "")
        return
    for value in references.splitlines():
        ref_path = value.removeprefix(b"refs/heads/").removeprefix(b"refs/tags/")
        if _has_unsafe_text(value) or _unsafe_git_name(ref_path):
            add("RG-GIT-NAME", "")
    object_ids: set[bytes] = set()
    object_names: dict[bytes, set[bytes]] = {}
    commit_ids: set[bytes] = set()
    blob_ids: set[bytes] = set()
    for line in objects.splitlines():
        object_id, _, member = line.partition(b" ")
        if not re.fullmatch(rb"[0-9a-f]{40,64}", object_id):
            add("RG-GIT-READ", "")
            continue
        object_ids.add(object_id)
        if member:
            object_names.setdefault(object_id, set()).add(member)
    for object_id in sorted(object_ids):
        object_type = _git_output(root, "cat-file", "-t", object_id.decode("ascii"))
        if object_type is None:
            add("RG-GIT-READ", "")
            continue
        kind = object_type.strip()
        if kind == b"commit":
            commit_ids.add(object_id)
        elif kind == b"blob":
            blob_ids.add(object_id)
        if kind not in {b"blob", b"commit", b"tag", b"tree"}:
            add("RG-GIT-READ", "")
            continue
        for member in object_names.get(object_id, set()):
            approved_github_ancestor = kind == b"tree" and member == b".github"
            if not approved_github_ancestor and (
                _has_unsafe_text(member) or _unsafe_git_name(member)
            ):
                add("RG-GIT-NAME", "")
        if kind in {b"commit", b"tag"}:
            content = _git_output(root, "cat-file", "-p", object_id.decode("ascii"))
            if content is None:
                add("RG-GIT-READ", "")
                continue
            scannable = _git_object_scannable_content(content, kind)
            if scannable is None:
                add("RG-GIT-READ", "")
            elif _content_rule_ids(scannable, ""):
                add("RG-GIT-CONTENT", "")
    scanned_blobs: set[tuple[bytes, str]] = set()
    for commit_id in sorted(commit_ids):
        tree = _git_output(root, "ls-tree", "-rz", "--full-tree", commit_id.decode("ascii"))
        if tree is None:
            add("RG-GIT-READ", "")
            continue
        for record in tree.split(b"\0"):
            if not record:
                continue
            metadata, separator, member = record.partition(b"\t")
            fields = metadata.split(b" ")
            if separator != b"\t" or len(fields) != 3:
                add("RG-GIT-READ", "")
                continue
            mode, object_type, object_id = fields
            if not re.fullmatch(rb"[0-9a-f]{40,64}", object_id):
                add("RG-GIT-READ", "")
                continue
            if mode == b"160000" or object_type == b"commit":
                add("RG-GIT-SUBMODULE", "")
            if _unsafe_git_name(member) or _has_unsafe_text(member):
                add("RG-GIT-NAME", "")
            if object_type != b"blob":
                continue
            try:
                member_text = member.decode("utf-8")
            except UnicodeDecodeError:
                member_text = ""
            logical_path = _safe_relative(member_text) or ""
            key = (object_id, logical_path)
            if key in scanned_blobs:
                continue
            scanned_blobs.add(key)
            content = _git_output(root, "cat-file", "-p", object_id.decode("ascii"))
            if content is None:
                add("RG-GIT-READ", "")
                continue
            for rule_id in _content_rule_ids(content, logical_path):
                add(rule_id, logical_path)
    tree_blob_ids = {object_id for object_id, _logical_path in scanned_blobs}
    for object_id in sorted(blob_ids - tree_blob_ids):
        content = _git_output(root, "cat-file", "-p", object_id.decode("ascii"))
        if content is None:
            add("RG-GIT-READ", "")
            continue
        for rule_id in _content_rule_ids(content, ""):
            add(rule_id, "")
    unreachable = _git_output(root, "fsck", "--no-reflogs", "--unreachable")
    reflog = _git_output(root, "reflog", "show", "--all")
    if unreachable is None or reflog is None:
        add("RG-GIT-READ", "")
    elif unreachable.strip():
        add("RG-GIT-UNREACHABLE", "")
    elif reflog.strip():
        add("RG-GIT-REFLOG", "")


def _project_details(root: Path) -> tuple[str, str, set[str]]:
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = data.get("project", {})
        name = str(project.get("name", ""))
        version = str(project.get("version", ""))
        dependency_values = project.get("dependencies", [])
        if not isinstance(dependency_values, list) or any(
            not isinstance(value, str) for value in dependency_values
        ):
            return "", "", set()
        dependencies = {value.strip() for value in dependency_values}
        return name, version, dependencies
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, AttributeError):
        return "", "", set()


def _license_contract(root: Path, add: _AddIssue) -> tuple[bytes | None, bytes | None]:
    try:
        license_bytes = (root / "LICENSE").read_bytes()
    except OSError:
        add("RG-LICENSE-MISSING", "LICENSE")
        license_bytes = None
    if (
        license_bytes is not None
        and hashlib.sha256(license_bytes).hexdigest() != _APACHE_LICENSE_SHA256
    ):
        add("RG-LICENSE-CONTENT", "LICENSE")
    try:
        notice_bytes = (root / "NOTICE").read_bytes()
    except OSError:
        add("RG-NOTICE", "NOTICE")
        notice_bytes = None
    else:
        if notice_bytes != _NOTICE_BYTES:
            add("RG-NOTICE", "NOTICE")
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
    except (KeyError, OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, TypeError):
        add("RG-PROJECT-LICENSE", "pyproject.toml")
    else:
        authors = project.get("authors") if isinstance(project, dict) else None
        if (
            not isinstance(project, dict)
            or project.get("license") != "Apache-2.0"
            or project.get("license-files") != ["LICENSE", "NOTICE"]
            or authors != [{"name": "liver-detox"}]
        ):
            add("RG-PROJECT-LICENSE", "pyproject.toml")
    return license_bytes, notice_bytes


def _valid_artifact_license_metadata(content: bytes) -> bool:
    metadata = BytesParser().parsebytes(content)
    return (
        metadata.get_all("License-Expression") == ["Apache-2.0"]
        and metadata.get_all("Author") == ["liver-detox"]
        and metadata.get_all("License-File") == ["LICENSE", "NOTICE"]
    )


def _artifact_members(
    artifact: Path, root: Path, expected_source: set[str], add: _AddIssue
) -> None:
    name, version, _ = _project_details(root)
    expected_dependencies = _project_metadata_requirements(root)
    source_license, source_notice = _license_contract(root, lambda _rule, _path: None)
    prefix = f"{name.replace('-', '_')}-{version}.dist-info" if name and version else ""
    package_prefix = f"src/{name.replace('-', '_')}/" if name else ""
    expected_wheel = {
        f"{name.replace('-', '_')}/{source.removeprefix(package_prefix)}"
        for source in expected_source
        if package_prefix and source.startswith(package_prefix)
    }
    if prefix:
        expected_wheel |= {
            f"{prefix}/METADATA",
            f"{prefix}/RECORD",
            f"{prefix}/WHEEL",
            f"{prefix}/entry_points.txt",
            f"{prefix}/licenses/LICENSE",
            f"{prefix}/licenses/NOTICE",
        }
    expected_sdist = {
        source
        for source in expected_source
        if source in _SDIST_ROOT_FILES
        or source in _SDIST_DOCS
        or source.startswith(("src/", "tests/", "examples/", "scripts/"))
    } | {"PKG-INFO"}
    seen: set[str] = set()
    logical_seen: set[str] = set()
    license_members: dict[str, bytes] = {}
    metadata_content: bytes | None = None

    def check_member(member: str, kind: str, content: bytes | None = None) -> None:
        nonlocal metadata_content
        archive_path = _safe_relative(member)
        label = f"artifact/{artifact.name}/{archive_path or 'invalid'}"
        if archive_path is None:
            add("RG-ARTIFACT-PATH", label)
            return
        if archive_path in seen:
            add("RG-ARTIFACT-DUPLICATE", label)
        seen.add(archive_path)
        if _is_private(archive_path):
            add("RG-ARTIFACT-PRIVATE", label)
        expected = expected_wheel if kind == "wheel" else expected_sdist
        expected_path = archive_path
        logical_path = archive_path
        if kind == "sdist" and name and version:
            root_prefix = f"{name}-{version}/"
            if not archive_path.startswith(root_prefix):
                add("RG-ARTIFACT-PATH", label)
                return
            expected_path = archive_path.removeprefix(root_prefix)
            logical_path = expected_path
        elif kind == "wheel" and package_prefix:
            wheel_package = package_prefix.removeprefix("src/")
            if archive_path.startswith(wheel_package):
                logical_path = f"src/{archive_path}"
        logical_seen.add(expected_path)
        if expected_path not in expected:
            add("RG-ARTIFACT-UNKNOWN", label)
        if content is not None:
            if kind == "wheel" and prefix:
                if expected_path == f"{prefix}/METADATA":
                    metadata_content = content
                elif expected_path in {
                    f"{prefix}/licenses/LICENSE",
                    f"{prefix}/licenses/NOTICE",
                }:
                    license_members[expected_path] = content
            elif kind == "sdist":
                if expected_path == "PKG-INFO":
                    metadata_content = content
                elif expected_path in {"LICENSE", "NOTICE"}:
                    license_members[expected_path] = content
            license_path = (kind == "sdist" and expected_path == "LICENSE") or (
                kind == "wheel" and prefix and expected_path == f"{prefix}/licenses/LICENSE"
            )
            _scan_text(content, "LICENSE" if license_path else logical_path, label, add)

    def check_license_contract(kind: str) -> None:
        if kind == "wheel" and prefix:
            expected_license_members = {
                f"{prefix}/licenses/LICENSE": source_license,
                f"{prefix}/licenses/NOTICE": source_notice,
            }
        else:
            expected_license_members = {"LICENSE": source_license, "NOTICE": source_notice}
        if (
            metadata_content is None
            or not _valid_artifact_license_metadata(metadata_content)
            or any(
                license_members.get(member) != content
                for member, content in expected_license_members.items()
            )
        ):
            add("RG-ARTIFACT-LICENSE", f"artifact/{artifact.name}")
        if metadata_content is None or expected_dependencies is None:
            add("RG-ARTIFACT-DEPENDENCIES", f"artifact/{artifact.name}")
            return
        metadata = BytesParser().parsebytes(metadata_content)
        artifact_dependencies = _normalized_requirements(
            tuple(metadata.get_all("Requires-Dist", []))
        )
        if artifact_dependencies is None or artifact_dependencies != expected_dependencies:
            add("RG-ARTIFACT-DEPENDENCIES", f"artifact/{artifact.name}")

    try:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as archive:
                for item in archive.infolist():
                    safe_name = _safe_relative(item.filename)
                    mode = item.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    label = f"artifact/{artifact.name}/{safe_name or 'invalid'}"
                    if file_type == stat.S_IFLNK:
                        add("RG-ARTIFACT-SYMLINK", label)
                        if safe_name is None:
                            add("RG-ARTIFACT-PATH", label)
                        continue
                    if item.is_dir():
                        if file_type in {0, stat.S_IFDIR}:
                            safe_name = _safe_relative(item.filename.removesuffix("/"))
                            label = f"artifact/{artifact.name}/{safe_name or 'invalid'}"
                            if safe_name is None:
                                add("RG-ARTIFACT-PATH", label)
                        if file_type not in {0, stat.S_IFDIR}:
                            add("RG-ARTIFACT-SPECIAL", label)
                        continue
                    if safe_name is None:
                        add("RG-ARTIFACT-PATH", label)
                        continue
                    if file_type not in {0, stat.S_IFREG}:
                        add("RG-ARTIFACT-SPECIAL", label)
                        continue
                    if mode & 0o111:
                        add(
                            "RG-ARTIFACT-EXECUTABLE",
                            f"artifact/{artifact.name}/{item.filename}",
                        )
                    check_member(item.filename, "wheel", archive.read(item))
                for missing in sorted(expected_wheel - logical_seen):
                    add("RG-ARTIFACT-MISSING", f"artifact/{artifact.name}/{missing}")
                check_license_contract("wheel")
        elif artifact.name.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(artifact, "r:*") as tar_archive:
                for tar_member in tar_archive.getmembers():
                    safe_name = _safe_relative(tar_member.name)
                    label = f"artifact/{artifact.name}/{safe_name or 'invalid'}"
                    if tar_member.issym():
                        add("RG-ARTIFACT-SYMLINK", label)
                        if safe_name is None:
                            add("RG-ARTIFACT-PATH", label)
                        continue
                    if tar_member.islnk():
                        add("RG-ARTIFACT-HARDLINK", label)
                        if safe_name is None:
                            add("RG-ARTIFACT-PATH", label)
                        continue
                    if tar_member.isdir():
                        safe_name = _safe_relative(tar_member.name.removesuffix("/"))
                        label = f"artifact/{artifact.name}/{safe_name or 'invalid'}"
                        if safe_name is None:
                            add("RG-ARTIFACT-PATH", label)
                        continue
                    if safe_name is None:
                        add("RG-ARTIFACT-PATH", label)
                        continue
                    if not tar_member.isfile():
                        add("RG-ARTIFACT-SPECIAL", label)
                        continue
                    if tar_member.mode & 0o111:
                        root_prefix = f"{name}-{version}/"
                        logical_name = safe_name.removeprefix(root_prefix)
                        if logical_name != "scripts/audit_release.py":
                            add("RG-ARTIFACT-EXECUTABLE", label)
                    extracted = tar_archive.extractfile(tar_member)
                    check_member(
                        tar_member.name, "sdist", extracted.read() if extracted is not None else b""
                    )
                for missing in sorted(expected_sdist - logical_seen):
                    add("RG-ARTIFACT-MISSING", f"artifact/{artifact.name}/{missing}")
                check_license_contract("sdist")
        else:
            add("RG-ARTIFACT-FORMAT", f"artifact/{artifact.name}")
    except (OSError, zipfile.BadZipFile, tarfile.TarError):
        add("RG-ARTIFACT-READ", f"artifact/{artifact.name}")


def audit_release(
    root: Path | str,
    *,
    allowlist: Path | str | None = None,
    dependency_register: Path | str | None = None,
    sbom: Path | str | None = None,
    artifacts: Sequence[Path | str] = (),
) -> AuditResult:
    """Audit an explicit local candidate without network access or unsafe output."""
    root_path = Path(root).resolve()
    issues: set[AuditIssue] = set()

    def add(rule_id: str, path: str) -> None:
        safe = _safe_relative(path) if path else ""
        if safe is not None and _has_unsafe_text(safe.encode("utf-8")):
            safe = ""
        issues.add(AuditIssue(rule_id, safe or ""))

    if not root_path.is_dir():
        add("RG-SOURCE-ROOT", "")
        return AuditResult(tuple(sorted(issues)))
    allowlist_path = (
        Path(allowlist) if allowlist is not None else root_path / "public-allowlist.txt"
    )
    register_path = Path(dependency_register) if dependency_register is not None else None
    sbom_path = Path(sbom) if sbom is not None else None
    expected = _read_allowlist(allowlist_path, add)
    actual = _source_members(root_path, expected, add)
    for member in sorted(actual - expected):
        add("RG-ALLOWLIST-MISSING", member)
    for member in sorted(expected - actual):
        add("RG-ALLOWLIST-UNKNOWN", member)
    _license_contract(root_path, add)
    _read_register(register_path, root_path, sbom_path, add)
    _audit_workflows(root_path, add)
    _audit_git(root_path, add)
    for artifact in artifacts:
        _artifact_members(Path(artifact), root_path, expected, add)
    return AuditResult(tuple(sorted(issues)))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local release auditor and emit safe deterministic output."""
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("root")
    parser.add_argument("--allowlist")
    parser.add_argument("--register")
    parser.add_argument("--sbom")
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)
    result = audit_release(
        arguments.root,
        allowlist=arguments.allowlist,
        dependency_register=arguments.register,
        sbom=arguments.sbom,
        artifacts=tuple(arguments.artifact),
    )
    print(result.to_json() if arguments.json else result.to_human(), end="")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
