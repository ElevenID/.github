from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any


MARKER = "<!-- elevenid-feature-regression-review:v2 -->"
SCHEMA = "elevenid.feature-regression-review/v2"
CANONICAL_JSON_METHOD = "elevenid-deterministic-json-v1"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,254}@sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TEST_REFERENCE = re.compile(
    r"^test:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<commit>[0-9a-f]{40}):(?P<path>[A-Za-z0-9_.\-/]+)::"
    r"(?P<test>[A-Za-z0-9_.:/#\-\[\]]+)$"
)
ARTIFACT_OBSERVATION_REFERENCE = re.compile(
    r"^artifact-observation:"
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<run_id>[1-9][0-9]*):(?P<observation>[A-Za-z0-9_.-]+)$"
)
CATALOG_REFERENCE = re.compile(
    r"^catalog:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<commit>[0-9a-f]{40}):(?P<path>[A-Za-z0-9_.\-/]+)$"
)
DECISION_REFERENCE = re.compile(
    r"^decision:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<commit>[0-9a-f]{40}):(?P<path>[A-Za-z0-9_.\-/]+)#"
    r"(?P<decision>[A-Za-z0-9_.-]+)$"
)
MERGE_QUEUE_PR = re.compile(r"(?:^|/)pr-(?P<number>[1-9][0-9]*)(?:-|/|$)")
AUTHORITY_ASSOCIATIONS = {"COLLABORATOR", "MEMBER", "OWNER"}
AUTHORITY_ROLES = {"repository_maintainer"}
DISPOSITIONS = {"preserved", "moved", "intentionally_changed", "unreachable"}
SURFACES = (
    "entry_points",
    "request_validation",
    "success_behavior",
    "failure_semantics",
    "persistence_audit",
    "metrics_operator_diagnostics",
    "security_redaction",
    "failure_retry_concurrency",
    "configuration_deployment_consumers",
    "production_boundary_tests_demos",
)
TOP_LEVEL_FIELDS = {
    "schema",
    "repository",
    "reviewed_base",
    "reviewed_head",
    "applicability",
    "reviewer",
    "implementation_context",
    "sanitized_public_evidence",
    "behavior_catalog",
    "inventory_sources",
    "findings",
    "commands",
    "tests",
    "unexercised_surfaces",
    "residual_risks",
    "surface_coverage",
    "operations",
    "behavior_dispositions",
    "cross_boundary",
}
DOC_EXTENSIONS = {
    ".md",
    ".mdx",
    ".rst",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
}
ROOT_DOCS = {
    "changelog.md",
    "code_of_conduct.md",
    "contributing.md",
    "license",
    "license.md",
    "readme.md",
    "security.md",
    "support.md",
}
PRODUCTION_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".cpp",
    ".cs",
    ".dart",
    ".go",
    ".h",
    ".hpp",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".php",
    ".proto",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".wasm",
    ".yaml",
    ".yml",
}
PRODUCTION_FILENAMES = {
    "cargo.lock",
    "cargo.toml",
    "dockerfile",
    "makefile",
    "package-lock.json",
    "package.json",
    "pyproject.toml",
}
PRODUCTION_TOKENS = {
    ".github",
    "api",
    "apis",
    "chart",
    "charts",
    "config",
    "configs",
    "contract",
    "contracts",
    "deploy",
    "deployment",
    "deployments",
    "docker",
    "migration",
    "migrations",
    "openapi",
    "proto",
    "schema",
    "schemas",
    "script",
    "scripts",
    "service",
    "services",
    "src",
    "workflow",
    "workflows",
}
EMAIL = re.compile(
    r"(?i)(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
AUTHORIZATION_VALUE = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])(?:[\"']?authorization[\"']?\s*[:=]\s*"
    r"[\"']?(?:(?:basic|bearer)\s+)?[^\s\"',}\]]+|bearer\s+\S+)"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?ix)(?<![A-Za-z0-9_])[\"']?(?:access[_-]?token|client[_-]?secret|"
    r"api[_-]?key|password|private[_-]?key|secret|token)[\"']?\s*[:=]\s*"
    r"[\"']?[^\s\"',}\]]+"
)
SECRET_KEY = re.compile(
    r"(?i)^(?:access[_-]?token|client[_-]?secret|api[_-]?key|password|"
    r"private[_-]?key|secret|token|authorization)$"
)
SAFE_SECRET_SENTINELS = {"not_exposed", "not_configured", "redacted", "none"}
STANDALONE_SECRET = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:ghp_[A-Za-z0-9_]{4,}|"
    r"github_pat_[A-Za-z0-9_]{4,}|sk-[A-Za-z0-9_-]{4,}|"
    r"xox[A-Za-z0-9-]*-[A-Za-z0-9-]{4,})(?![A-Za-z0-9])"
)
PRIVATE_KEY_MATERIAL = re.compile(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
PHONE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})"
    r"[ .-]?[0-9]{3}[ .-]?[0-9]{4}(?![A-Za-z0-9])"
)
SECRET_PATH_MATERIAL = re.compile(
    r"(?i)(?:token|secret|passwd|password|credential|privatekey|apikey|"
    r"clientsecret|accesstoken|accesskey|bearer|authorization|"
    r"githubpat|ghp[A-Za-z0-9]{8,}|sk[A-Za-z0-9]{8,}|xox[A-Za-z0-9]{8,})"
)
ARTIFACT_STORAGE_HOST = re.compile(
    r"(?i)^(?:[A-Za-z0-9-]+\.)?(?:blob\.core\.windows\.net|"
    r"actions\.githubusercontent\.com)$"
)
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_OBSERVATION_BYTES = 2 * 1024 * 1024
ATOMIC_PRODUCE_STEP_NAME = "Produce trusted runtime observations atomically"
UPLOAD_OBSERVATIONS_STEP_NAME = "Upload runtime observations"


class EvidenceError(ValueError):
    """Feature-regression evidence or its authoritative source is invalid."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class ReviewTarget:
    number: int
    base_sha: str
    head_sha: str


ContentFetcher = Callable[[str, str, str], bytes]
RunFetcher = Callable[[str, int], Mapping[str, Any]]
JobsFetcher = Callable[[str, int, int], list[Mapping[str, Any]]]
ArtifactsFetcher = Callable[[str, int], list[Mapping[str, Any]]]
ArtifactDownloader = Callable[[str, int], bytes]
AuthorityResolver = Callable[[str], Mapping[str, Any]]
DecisionFetcher = Callable[[str], bytes]


@dataclass(frozen=True)
class TestReference:
    repository: str
    commit: str
    path: str
    token: str


@dataclass(frozen=True)
class InventorySource:
    repository: str
    path: str
    commit: str
    phase: str

    @property
    def content_tuple(self) -> tuple[str, str, str]:
        return self.repository, self.path, self.commit

    @property
    def normalized_content_tuple(self) -> tuple[str, str, str]:
        return self.repository.casefold(), self.path, self.commit


@dataclass(frozen=True)
class ArtifactReference:
    repository: str
    run_id: int


@dataclass(frozen=True)
class ArtifactObservationReference:
    repository: str
    run_id: int
    observation_id: str


@dataclass(frozen=True)
class ProducerContract:
    workflow_path: str
    workflow_sha256: str
    central_workflow_sha: str
    harness_path: str
    harness_sha256: str
    subject_path: str
    subject_sha256: str
    subject_runtime: str
    subject_args: tuple[str, ...]
    subject_env: dict[str, str]
    runtime_image: str
    job_name: str
    produce_step_name: str
    upload_step_name: str
    artifact_name_prefix: str
    observation_path: str


@dataclass(frozen=True)
class CatalogSelection:
    cases: dict[str, tuple[str, str, set[str]]]
    producer: ProducerContract


@dataclass(frozen=True)
class CatalogReference:
    repository: str
    commit: str
    path: str


@dataclass(frozen=True)
class DecisionReference:
    repository: str
    commit: str
    path: str
    decision_id: str


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError(f"{path} must be an object")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{path} must be an array")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{path} must be a non-empty string")
    return value.strip()


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{path} must be a boolean")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    if missing or extra:
        raise EvidenceError(
            f"{path} fields do not match the schema; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )


def _validate_sanitized_strings(value: Any, path: str = "evidence") -> None:
    if isinstance(value, Mapping):
        for index, (key, child) in enumerate(value.items()):
            if (
                isinstance(key, str)
                and SECRET_KEY.fullmatch(key)
                and (
                    not isinstance(child, str)
                    or child.casefold() not in SAFE_SECRET_SENTINELS
                )
            ):
                raise EvidenceError(
                    f"{path}.{key} contains a prohibited secret assignment"
                )
            _validate_sanitized_strings(key, f"{path}.<key[{index}]>")
            _validate_sanitized_strings(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_sanitized_strings(child, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvidenceError(f"{path} contains a prohibited control character")
    candidates = re.findall(r"https?://[^\s]+", value.removeprefix("artifact:"))
    for candidate in candidates:
        parsed = urllib.parse.urlparse(candidate)
        if (
            parsed.username
            or parsed.password
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise EvidenceError(
                f"{path} contains a URL with userinfo, query, or fragment"
            )
        for segment in parsed.path.split("/"):
            if not segment:
                continue
            decoded = segment
            try:
                for _ in range(4):
                    next_value = urllib.parse.unquote(decoded, errors="strict")
                    if next_value == decoded:
                        break
                    decoded = next_value
            except UnicodeDecodeError as error:
                raise EvidenceError(
                    f"{path} contains invalid URL path encoding"
                ) from error
            if re.search(r"%[0-9A-Fa-f]{2}", decoded):
                raise EvidenceError(f"{path} contains nested URL path encoding")
            normalized = re.sub(r"[^A-Za-z0-9]", "", decoded)
            if SECRET_PATH_MATERIAL.search(normalized):
                raise EvidenceError(f"{path} contains secret-like URL path material")
    if AUTHORIZATION_VALUE.search(value):
        raise EvidenceError(f"{path} contains a prohibited authorization value")
    if SECRET_ASSIGNMENT.search(value):
        raise EvidenceError(f"{path} contains a prohibited secret assignment")
    if STANDALONE_SECRET.search(value):
        raise EvidenceError(f"{path} contains a prohibited standalone secret")
    if PRIVATE_KEY_MATERIAL.search(value):
        raise EvidenceError(f"{path} contains prohibited private-key material")
    if PHONE.search(value):
        raise EvidenceError(f"{path} contains prohibited phone-shaped personal data")
    if EMAIL.search(value):
        raise EvidenceError(f"{path} contains prohibited email-shaped personal data")


def _sha(value: Any, path: str) -> str:
    digest = _text(value, path)
    if not SHA.fullmatch(digest):
        raise EvidenceError(f"{path} must be a 40-character lowercase SHA")
    return digest


def _repository(value: Any, path: str) -> str:
    repository = _text(value, path)
    if not REPOSITORY.fullmatch(repository):
        raise EvidenceError(f"{path} must be an owner/repository name")
    return repository


def _relative_path(value: Any, path: str) -> str:
    candidate = _text(value, path).replace("\\", "/")
    parts = candidate.split("/")
    if (
        candidate.startswith("/")
        or not all(parts)
        or any(part in {".", ".."} for part in parts)
        or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", candidate)
    ):
        raise EvidenceError(f"{path} must be a safe repository-relative path")
    return candidate


def _parse_test_reference(value: Any, path: str) -> TestReference:
    reference = _text(value, path)
    match = TEST_REFERENCE.fullmatch(reference)
    if match is None:
        raise EvidenceError(
            f"{path} must use test:<owner/repo>@<40sha>:<path>::<test token> syntax"
        )
    repository = _repository(match.group("repository"), f"{path} repository")
    commit = _sha(match.group("commit"), f"{path} commit")
    source_path = _relative_path(match.group("path"), f"{path} path")
    if not _is_test_path(source_path):
        raise EvidenceError(f"{path} path must be a recognized test path")
    token = _text(match.group("test"), f"{path} token")
    return TestReference(repository, commit, source_path, token)


def _test_reference(value: Any, path: str) -> str:
    reference = _text(value, path)
    _parse_test_reference(reference, path)
    return reference


def _parse_artifact_observation_reference(
    value: Any, path: str
) -> ArtifactObservationReference:
    reference = _text(value, path)
    match = ARTIFACT_OBSERVATION_REFERENCE.fullmatch(reference)
    if match is None:
        raise EvidenceError(
            f"{path} must use artifact-observation:<owner/repo>@<run id>:<id> syntax"
        )
    return ArtifactObservationReference(
        repository=_repository(match.group("repository"), f"{path} repository"),
        run_id=int(match.group("run_id")),
        observation_id=_text(match.group("observation"), f"{path} id"),
    )


def _parse_catalog_reference(value: Any, path: str) -> CatalogReference:
    reference = _text(value, path)
    match = CATALOG_REFERENCE.fullmatch(reference)
    if match is None:
        raise EvidenceError(
            f"{path} must use catalog:<owner/repo>@<40sha>:<path> syntax"
        )
    return CatalogReference(
        _repository(match.group("repository"), f"{path} repository"),
        _sha(match.group("commit"), f"{path} commit"),
        _relative_path(match.group("path"), f"{path} path"),
    )


def _parse_decision_reference(value: Any, path: str) -> DecisionReference:
    reference = _text(value, path)
    match = DECISION_REFERENCE.fullmatch(reference)
    if match is None:
        raise EvidenceError(
            f"{path} must use decision:<owner/repo>@<40sha>:<path>#<id> syntax"
        )
    return DecisionReference(
        _repository(match.group("repository"), f"{path} repository"),
        _sha(match.group("commit"), f"{path} commit"),
        _relative_path(match.group("path"), f"{path} path"),
        _text(match.group("decision"), f"{path} id"),
    )


def _parse_artifact_reference(value: Any, path: str) -> ArtifactReference:
    reference = _text(value, path)
    if not reference.startswith("artifact:"):
        raise EvidenceError(f"{path} must begin with 'artifact:'")
    parsed = urllib.parse.urlparse(reference.removeprefix("artifact:"))
    segments = [segment for segment in parsed.path.split("/") if segment]
    suffix = segments[5:]
    valid_suffix = not suffix or (
        len(suffix) == 2 and suffix[0] in {"artifacts", "job"} and suffix[1].isdigit()
    )
    valid = (
        parsed.scheme == "https"
        and parsed.netloc.casefold() == "github.com"
        and len(segments) >= 5
        and segments[0].casefold() == "elevenid"
        and segments[2:4] == ["actions", "runs"]
        and segments[4].isdigit()
        and valid_suffix
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )
    if not valid:
        raise EvidenceError(
            f"{path} must be an artifact:https://github.com/ElevenID/"
            "<repo>/actions/runs/<id> reference"
        )
    return ArtifactReference(
        repository=f"{segments[0]}/{segments[1]}", run_id=int(segments[4])
    )


def _artifact_reference(value: Any, path: str) -> str:
    reference = _text(value, path)
    _parse_artifact_reference(reference, path)
    return reference


def _evidence_reference(value: Any, path: str) -> str:
    reference = _text(value, path)
    if reference.startswith("test:"):
        return _test_reference(reference, path)
    if reference.startswith("artifact:"):
        return _artifact_reference(reference, path)
    if reference.startswith("artifact-observation:"):
        _parse_artifact_observation_reference(reference, path)
        return reference
    raise EvidenceError(
        f"{path} must be a strict test, artifact-observation, or "
        "ElevenID Actions artifact URL"
    )


def _evidence_references(value: Any, path: str) -> list[str]:
    references = _list(value, path)
    if not references:
        raise EvidenceError(f"{path} must contain at least one evidence reference")
    return [
        _evidence_reference(reference, f"{path}[{index}]")
        for index, reference in enumerate(references)
    ]


def _test_references(value: Any, path: str) -> list[str]:
    references = _list(value, path)
    if not references:
        raise EvidenceError(f"{path} must contain at least one test reference")
    return [
        _test_reference(reference, f"{path}[{index}]")
        for index, reference in enumerate(references)
    ]


def _validate_source_tuple(
    value: Any, path: str, *, include_digest: bool = False
) -> tuple[str, str, str]:
    source = _mapping(value, path)
    expected = {"repository", "path", "commit"}
    if include_digest:
        expected.add("sha256")
    _exact_keys(source, expected, path)
    repository = _repository(source.get("repository"), f"{path}.repository")
    source_path = _relative_path(source.get("path"), f"{path}.path")
    commit = _sha(source.get("commit"), f"{path}.commit")
    return repository, source_path, commit


def _validate_inventory_sources(value: Any) -> list[InventorySource]:
    sources = _list(value, "inventory_sources")
    if not sources:
        raise EvidenceError("inventory_sources must not be empty")
    seen: set[tuple[str, str, str]] = set()
    validated: list[InventorySource] = []
    for index, source in enumerate(sources):
        path = f"inventory_sources[{index}]"
        source = _mapping(source, path)
        _exact_keys(source, {"repository", "path", "commit", "phase"}, path)
        phase = _text(source.get("phase"), f"{path}.phase")
        if phase not in {"pre_change", "post_change"}:
            raise EvidenceError(f"{path}.phase must be pre_change or post_change")
        item = InventorySource(
            repository=_repository(source.get("repository"), f"{path}.repository"),
            path=_relative_path(source.get("path"), f"{path}.path"),
            commit=_sha(source.get("commit"), f"{path}.commit"),
            phase=phase,
        )
        if item.normalized_content_tuple in seen:
            raise EvidenceError("inventory_sources must contain unique tuples")
        seen.add(item.normalized_content_tuple)
        validated.append(item)
    return validated


def _validate_findings(value: Any) -> None:
    findings = _list(value, "findings")
    for index, value in enumerate(findings):
        path = f"findings[{index}]"
        finding = _mapping(value, path)
        _exact_keys(finding, {"severity", "status", "summary", "evidence"}, path)
        severity = _text(finding.get("severity"), f"{path}.severity")
        if severity not in {"blocking", "high", "medium", "low"}:
            raise EvidenceError(
                f"{path}.severity must be blocking, high, medium, or low"
            )
        status = _text(finding.get("status"), f"{path}.status")
        if status not in {"resolved", "accepted"}:
            raise EvidenceError(f"{path}.status must be resolved or accepted")
        if severity == "blocking" and status != "resolved":
            raise EvidenceError(f"{path} is an unresolved blocking finding")
        _text(finding.get("summary"), f"{path}.summary")
        _evidence_references(finding.get("evidence"), f"{path}.evidence")


def _validate_commands(value: Any) -> None:
    commands = _list(value, "commands")
    if not commands:
        raise EvidenceError("commands must not be empty")
    for index, command in enumerate(commands):
        text = _text(command, f"commands[{index}]")
        if "\n" in text or "\r" in text or len(text) > 500:
            raise EvidenceError(f"commands[{index}] must be one sanitized command line")


def _validate_named_rationales(value: Any, path: str) -> None:
    items = _list(value, path)
    for index, value in enumerate(items):
        item_path = f"{path}[{index}]"
        item = _mapping(value, item_path)
        _exact_keys(item, {"surface", "rationale"}, item_path)
        _text(item.get("surface"), f"{item_path}.surface")
        _text(item.get("rationale"), f"{item_path}.rationale")


def _validate_residual_risks(value: Any) -> None:
    risks = _list(value, "residual_risks")
    for index, risk in enumerate(risks):
        _text(risk, f"residual_risks[{index}]")


def _validate_coverage(value: Any, path: str, *, allow_not_applicable: bool) -> None:
    coverage = _mapping(value, path)
    has_evidence = "evidence" in coverage
    has_not_applicable = "not_applicable" in coverage
    if has_evidence == has_not_applicable:
        raise EvidenceError(
            f"{path} must contain exactly one of evidence or not_applicable"
        )
    if has_not_applicable:
        if not allow_not_applicable:
            raise EvidenceError(
                f"{path}.not_applicable is forbidden for production-affecting changes"
            )
        _exact_keys(coverage, {"not_applicable"}, path)
        _text(coverage["not_applicable"], f"{path}.not_applicable")
    else:
        _exact_keys(coverage, {"evidence"}, path)
        _evidence_references(coverage["evidence"], f"{path}.evidence")


def _validate_surface_coverage(value: Any, *, allow_not_applicable: bool) -> None:
    coverage = _mapping(value, "surface_coverage")
    missing = set(SURFACES) - set(coverage)
    extra = set(coverage) - set(SURFACES)
    if missing or extra:
        raise EvidenceError(
            "surface_coverage must contain exactly the ten contract surfaces; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    for surface in SURFACES:
        _validate_coverage(
            coverage[surface],
            f"surface_coverage.{surface}",
            allow_not_applicable=allow_not_applicable,
        )


def _validate_snapshot(value: Any, path: str) -> Any:
    snapshot = _mapping(value, path)
    _exact_keys(snapshot, {"value", "evidence"}, path)
    if "value" not in snapshot:
        raise EvidenceError(f"{path}.value is required")
    snapshot_value = snapshot["value"]
    try:
        json.dumps(snapshot_value, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"{path}.value must be finite JSON data") from error
    _evidence_references(snapshot.get("evidence"), f"{path}.evidence")
    return snapshot_value


def _validate_change_decision(
    value: Any,
    path: str,
    *,
    reviewer_login: str,
    repository: str,
    reviewed_base: str,
    scope: Mapping[str, str],
    expected_before: Any | None,
    expected_after: Any | None,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> None:
    decision = _mapping(value, path)
    _exact_keys(
        decision,
        {
            "approved_by",
            "authority_role",
            "decision_ref",
            "compatibility_impact",
            "replacement_behavior",
            "breaking_loss",
            "before_value",
            "after_value",
        },
        path,
    )
    approved_by = _text(decision.get("approved_by"), f"{path}.approved_by")
    if approved_by.casefold() != reviewer_login.casefold():
        raise EvidenceError(f"{path}.approved_by must match the evidence commenter")
    authority = _text(decision.get("authority_role"), f"{path}.authority_role")
    if authority not in AUTHORITY_ROLES:
        raise EvidenceError(f"{path}.authority_role must be repository_maintainer")
    resolved = _mapping(
        authority_resolver(approved_by), f"{path}.approved_by permission"
    )
    permission = _text(
        resolved.get("permission"), f"{path}.approved_by permission"
    ).casefold()
    role_name = _text(
        resolved.get("role_name"), f"{path}.approved_by role_name"
    ).casefold()
    # GitHub's legacy `permission` field reports the maintain role as `write`;
    # `role_name` carries the exact repository role.  Require a consistent
    # maintain/admin pair instead of trusting either field in isolation.
    allowed_authority = {
        ("write", "maintain"),
        ("maintain", "maintain"),
        ("admin", "admin"),
    }
    if (permission, role_name) not in allowed_authority:
        raise EvidenceError(
            f"{path}.approved_by must have GitHub maintain/admin permission and role_name"
        )
    decision_ref = _parse_decision_reference(
        decision.get("decision_ref"), f"{path}.decision_ref"
    )
    if (
        decision_ref.repository.casefold() != repository.casefold()
        or decision_ref.commit != reviewed_base
    ):
        raise EvidenceError(
            f"{path}.decision_ref must be in the reviewed repository at reviewed_base"
        )
    impact = _text(decision.get("compatibility_impact"), f"{path}.compatibility_impact")
    replacement = _text(
        decision.get("replacement_behavior"), f"{path}.replacement_behavior"
    )
    breaking_loss = _bool(decision.get("breaking_loss"), f"{path}.breaking_loss")
    before_value = decision.get("before_value")
    after_value = decision.get("after_value")
    if expected_before is not None and _deterministic_json_bytes(
        before_value
    ) != _deterministic_json_bytes(expected_before):
        raise EvidenceError(
            f"{path}.before_value does not match the operation snapshot"
        )
    if expected_after is not None and _deterministic_json_bytes(
        after_value
    ) != _deterministic_json_bytes(expected_after):
        raise EvidenceError(f"{path}.after_value does not match the operation snapshot")
    before_digest = (
        f"sha256:{hashlib.sha256(_deterministic_json_bytes(before_value)).hexdigest()}"
    )
    after_digest = (
        f"sha256:{hashlib.sha256(_deterministic_json_bytes(after_value)).hexdigest()}"
    )
    decision_document = _mapping(
        _parse_strict_json(
            decision_fetcher(str(decision.get("decision_ref"))), "decision document"
        ),
        "decision document",
    )
    _validate_sanitized_strings(decision_document, "decision document")
    _exact_keys(decision_document, {"schema", "decisions"}, "decision document")
    if decision_document.get("schema") != "elevenid.intentional-change-decisions/v1":
        raise EvidenceError("decision document schema is invalid")
    matches = [
        _mapping(item, "decision record")
        for item in _list(
            decision_document.get("decisions"), "decision document.decisions"
        )
        if isinstance(item, Mapping) and item.get("id") == decision_ref.decision_id
    ]
    if len(matches) != 1:
        raise EvidenceError("decision_ref must select exactly one decision record")
    record = matches[0]
    _exact_keys(
        record,
        {
            "id",
            "repository",
            "scope",
            "approved_by",
            "before_value",
            "after_value",
            "before_sha256",
            "after_sha256",
            "compatibility_impact",
            "replacement_behavior",
            "breaking_loss",
        },
        "decision record",
    )
    expected = {
        "id": decision_ref.decision_id,
        "repository": repository,
        "scope": dict(scope),
        "approved_by": approved_by,
        "before_value": before_value,
        "after_value": after_value,
        "before_sha256": before_digest,
        "after_sha256": after_digest,
        "compatibility_impact": impact,
        "replacement_behavior": replacement,
        "breaking_loss": breaking_loss,
    }
    for field, expected_value in expected.items():
        if record.get(field) != expected_value:
            raise EvidenceError(f"decision record {field} does not match evidence")


def _validate_test_mapping(value: Any, path: str) -> None:
    mapping = _mapping(value, path)
    if set(mapping) != {"before", "after"}:
        raise EvidenceError(f"{path} must contain exactly before and after")
    _test_reference(mapping["before"], f"{path}.before")
    _test_reference(mapping["after"], f"{path}.after")


def _validate_comparison(
    value: Any,
    path: str,
    *,
    reviewer_login: str,
    repository: str,
    reviewed_base: str,
    operation_name: str,
    dimension: str,
    allow_not_applicable: bool,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> None:
    comparison = _mapping(value, path)
    disposition = _text(comparison.get("disposition"), f"{path}.disposition")
    if disposition == "not_applicable":
        if not allow_not_applicable:
            raise EvidenceError(
                f"{path}.disposition not_applicable is forbidden for "
                "production-affecting changes"
            )
        _exact_keys(comparison, {"disposition", "rationale"}, path)
        _text(comparison.get("rationale"), f"{path}.rationale")
        if "before" in comparison or "after" in comparison:
            raise EvidenceError(
                f"{path} not_applicable comparison may not contain before/after"
            )
        return
    if disposition not in {"preserved", "moved", "intentionally_changed"}:
        raise EvidenceError(
            f"{path}.disposition must be preserved, moved, intentionally_changed, "
            "or not_applicable"
        )
    expected = {"disposition", "before", "after"}
    if disposition == "moved":
        expected.update({"moved_owner", "test_mapping"})
    elif disposition == "intentionally_changed":
        expected.add("decision")
    _exact_keys(comparison, expected, path)
    before = _validate_snapshot(comparison.get("before"), f"{path}.before")
    after = _validate_snapshot(comparison.get("after"), f"{path}.after")
    values_equal = _deterministic_json_bytes(before) == _deterministic_json_bytes(after)
    if disposition in {"preserved", "moved"} and not values_equal:
        raise EvidenceError(
            f"{path} changed from before to after and must be intentionally_changed"
        )
    if disposition == "moved":
        _repository(comparison.get("moved_owner"), f"{path}.moved_owner")
        _validate_test_mapping(comparison.get("test_mapping"), f"{path}.test_mapping")
    if disposition == "intentionally_changed":
        if values_equal:
            raise EvidenceError(
                f"{path} is unchanged and may not be intentionally_changed"
            )
        _validate_change_decision(
            comparison.get("decision"),
            f"{path}.decision",
            reviewer_login=reviewer_login,
            repository=repository,
            reviewed_base=reviewed_base,
            scope={
                "kind": "operation_dimension",
                "operation": operation_name,
                "dimension": dimension,
            },
            expected_before=before,
            expected_after=after,
            authority_resolver=authority_resolver,
            decision_fetcher=decision_fetcher,
        )


def _validate_operations(
    value: Any,
    *,
    reviewer_login: str,
    repository: str,
    reviewed_base: str,
    allow_not_applicable: bool,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> None:
    operations = _list(value, "operations")
    if not operations:
        raise EvidenceError("operations must describe every affected operation")
    names: set[str] = set()
    for index, value in enumerate(operations):
        path = f"operations[{index}]"
        operation = _mapping(value, path)
        _exact_keys(
            operation,
            {
                "id",
                "case_id",
                "name",
                "public_status",
                "public_message",
                "safe_server_diagnostic",
            },
            path,
        )
        _text(operation.get("id"), f"{path}.id")
        _text(operation.get("case_id"), f"{path}.case_id")
        name = _text(operation.get("name"), f"{path}.name")
        normalized = name.casefold()
        if normalized in names:
            raise EvidenceError(f"{path}.name duplicates another operation")
        names.add(normalized)
        for field in ("public_status", "public_message", "safe_server_diagnostic"):
            _validate_comparison(
                operation.get(field),
                f"{path}.{field}",
                reviewer_login=reviewer_login,
                repository=repository,
                reviewed_base=reviewed_base,
                operation_name=name,
                dimension=field,
                allow_not_applicable=allow_not_applicable,
                authority_resolver=authority_resolver,
                decision_fetcher=decision_fetcher,
            )


def _validate_behavior_dispositions(
    value: Any,
    *,
    reviewer_login: str,
    repository: str,
    reviewed_base: str,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> None:
    dispositions = _list(value, "behavior_dispositions")
    if not dispositions:
        raise EvidenceError("behavior_dispositions must account for affected behavior")
    behaviors: set[str] = set()
    for index, value in enumerate(dispositions):
        path = f"behavior_dispositions[{index}]"
        item = _mapping(value, path)
        behavior = _text(item.get("behavior"), f"{path}.behavior")
        normalized = behavior.casefold()
        if normalized in behaviors:
            raise EvidenceError(f"{path}.behavior duplicates another disposition")
        behaviors.add(normalized)
        disposition = _text(item.get("disposition"), f"{path}.disposition")
        if disposition not in DISPOSITIONS:
            raise EvidenceError(
                f"{path}.disposition must be one of {sorted(DISPOSITIONS)}"
            )
        expected = {"behavior", "disposition", "evidence"}
        if disposition == "moved":
            expected.update({"new_owner", "test_mapping"})
        elif disposition == "intentionally_changed":
            expected.add("decision")
        _exact_keys(item, expected, path)
        _evidence_references(item.get("evidence"), f"{path}.evidence")
        if disposition == "moved":
            _repository(item.get("new_owner"), f"{path}.new_owner")
            _validate_test_mapping(item.get("test_mapping"), f"{path}.test_mapping")
        if disposition == "intentionally_changed":
            _validate_change_decision(
                item.get("decision"),
                f"{path}.decision",
                reviewer_login=reviewer_login,
                repository=repository,
                reviewed_base=reviewed_base,
                scope={"kind": "behavior", "behavior": behavior},
                expected_before=None,
                expected_after=None,
                authority_resolver=authority_resolver,
                decision_fetcher=decision_fetcher,
            )


def _reject_json_constant(value: str) -> None:
    raise EvidenceError(f"canonical JSON contains prohibited constant {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"canonical JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _deterministic_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _parse_strict_json(content: bytes, label: str) -> Any:
    try:
        return json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not strict JSON: {error}") from error


def canonical_json_digest(content: bytes) -> str:
    try:
        value = _parse_strict_json(content, "canonical JSON source")
        canonical = _deterministic_json_bytes(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError(
            f"source is not valid deterministic JSON: {error}"
        ) from error
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _raw_sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _expected_producer_workflow(producer: ProducerContract) -> bytes:
    subject_args_json = json.dumps(list(producer.subject_args), separators=(",", ":"))
    subject_env_json = json.dumps(
        producer.subject_env, sort_keys=True, separators=(",", ":")
    )
    content = f"""name: feature-regression-observation-producer

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions:
  actions: read
  contents: read

jobs:
  behavior-observations:
    uses: ElevenID/.github/.github/workflows/feature-regression-observation-producer.yml@{producer.central_workflow_sha}
    with:
      policy-ref: {producer.central_workflow_sha}
      target-ref: ${{{{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}}}
      phase: ${{{{ github.event_name == 'pull_request' && 'after' || 'before' }}}}
      workflow-path: {producer.workflow_path}
      harness-path: {producer.harness_path}
      harness-sha256: {producer.harness_sha256}
      subject-path: {producer.subject_path}
      subject-sha256: {producer.subject_sha256}
      subject-runtime: {producer.subject_runtime}
      subject-args-json: '{subject_args_json}'
      subject-env-json: '{subject_env_json}'
      runtime-image: {producer.runtime_image}
      job-name: {producer.job_name}
      artifact-name-prefix: {producer.artifact_name_prefix}
      observation-path: {producer.observation_path}
"""
    return content.encode("utf-8")


def _external_moved_owners(
    document: Mapping[str, Any], *, current_repository: str
) -> set[str]:
    owners: set[str] = set()
    for operation in _list(document.get("operations"), "operations"):
        operation = _mapping(operation, "operation")
        for field in ("public_status", "public_message", "safe_server_diagnostic"):
            comparison = _mapping(operation.get(field), f"operation.{field}")
            if comparison.get("disposition") == "moved":
                owner = _repository(comparison.get("moved_owner"), "moved_owner")
                if owner.casefold() != current_repository.casefold():
                    owners.add(owner.casefold())
    for disposition in _list(
        document.get("behavior_dispositions"), "behavior_dispositions"
    ):
        disposition = _mapping(disposition, "behavior_disposition")
        if disposition.get("disposition") == "moved":
            owner = _repository(disposition.get("new_owner"), "new_owner")
            if owner.casefold() != current_repository.casefold():
                owners.add(owner.casefold())
    return owners


def _validate_cross_boundary(
    value: Any,
    *,
    fetch_content: ContentFetcher,
    inventory_sources: list[InventorySource],
    current_repository: str,
    reviewed_head: str,
    required: bool,
    external_moved_owners: set[str],
) -> list[tuple[str, str, str]]:
    cross_boundary = _mapping(value, "cross_boundary")
    _exact_keys(
        cross_boundary,
        {"applies", "method", "common_sha256", "sources"},
        "cross_boundary",
    )
    applies = _bool(cross_boundary.get("applies"), "cross_boundary.applies")
    sources = _list(cross_boundary.get("sources"), "cross_boundary.sources")
    common_digest = cross_boundary.get("common_sha256")
    method = cross_boundary.get("method")
    if not applies:
        if sources or common_digest is not None or method is not None:
            raise EvidenceError(
                "cross_boundary false requires empty sources and null method/digest"
            )
        if required:
            raise EvidenceError(
                "cross_boundary.applies must be true for multi-repository inventory "
                "or externally moved behavior"
            )
        return []
    if method != CANONICAL_JSON_METHOD:
        raise EvidenceError(
            f"cross_boundary.method must equal {CANONICAL_JSON_METHOD!r}"
        )
    expected = _text(common_digest, "cross_boundary.common_sha256")
    if not DIGEST.fullmatch(expected):
        raise EvidenceError(
            "cross_boundary.common_sha256 must be sha256:<64 lowercase hex>"
        )
    if len(sources) < 2:
        raise EvidenceError("cross_boundary.sources must contain at least two tuples")
    seen: set[tuple[str, str, str]] = set()
    inventory_by_tuple = {
        source.normalized_content_tuple: source for source in inventory_sources
    }
    for index, value in enumerate(sources):
        path = f"cross_boundary.sources[{index}]"
        source = _mapping(value, path)
        item = _validate_source_tuple(source, path, include_digest=True)
        normalized_item = (item[0].casefold(), item[1], item[2])
        inventory_source = inventory_by_tuple.get(normalized_item)
        if inventory_source is None:
            raise EvidenceError(
                f"{path} must be an exact tuple declared in inventory_sources"
            )
        if normalized_item in seen:
            raise EvidenceError("cross_boundary.sources must contain unique tuples")
        seen.add(normalized_item)
        declared = _text(source.get("sha256"), f"{path}.sha256")
        if declared != expected:
            raise EvidenceError(f"{path}.sha256 does not equal common_sha256")
        actual = canonical_json_digest(fetch_content(*item))
        if actual != expected:
            raise EvidenceError(
                f"{path} content digest {actual} does not equal {expected}"
            )
    if not any(
        repository == current_repository.casefold()
        and commit == reviewed_head
        and inventory_by_tuple[(repository, source_path, commit)].phase == "post_change"
        for repository, source_path, commit in seen
    ):
        raise EvidenceError(
            "cross_boundary.sources must include the current repository at "
            "reviewed_head as a post_change inventory source"
        )
    source_repositories = {repository for repository, _path, _commit in seen}
    required_external_repositories = {
        source.repository.casefold()
        for source in inventory_sources
        if source.repository.casefold() != current_repository.casefold()
    }
    missing_owners = (
        external_moved_owners | required_external_repositories
    ) - source_repositories
    if missing_owners:
        raise EvidenceError(
            "cross_boundary.sources omit canonical contract sources for repositories: "
            + ", ".join(sorted(missing_owners))
        )
    return sorted(seen)


def _verify_test_reference(
    value: Any,
    path: str,
    *,
    allowed_repository_commits: set[tuple[str, str]],
    allowed_exact_sources: set[tuple[str, str, str]] | None = None,
    fetch_content: ContentFetcher,
) -> None:
    parsed = _parse_test_reference(value, path)
    repository_commit = (parsed.repository.casefold(), parsed.commit)
    exact_source = (parsed.repository.casefold(), parsed.path, parsed.commit)
    if repository_commit not in allowed_repository_commits and exact_source not in (
        allowed_exact_sources or set()
    ):
        raise EvidenceError(f"{path} is outside the permitted evidence phase")
    content = fetch_content(parsed.repository, parsed.path, parsed.commit)
    try:
        source = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{path} source is not strict UTF-8") from error
    if parsed.token not in source:
        raise EvidenceError(f"{path} token does not exist in exact source")


def _verify_artifact_reference(
    value: Any,
    path: str,
    *,
    expected_commit: str,
    fetch_run: RunFetcher,
) -> None:
    parsed = _parse_artifact_reference(value, path)
    run = _mapping(fetch_run(parsed.repository, parsed.run_id), f"{path} Actions run")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise EvidenceError(f"{path} Actions run must be completed successfully")
    if _sha(run.get("head_sha"), f"{path} Actions run head") != expected_commit:
        raise EvidenceError(
            f"{path} Actions run must bind the permitted evidence phase"
        )


def _verify_raw_reference(
    value: Any,
    path: str,
    *,
    allowed_test_repository_commits: set[tuple[str, str]],
    artifact_commit: str,
    fetch_content: ContentFetcher,
    fetch_run: RunFetcher,
) -> None:
    reference = _text(value, path)
    if reference.startswith("test:"):
        _verify_test_reference(
            reference,
            path,
            allowed_repository_commits=allowed_test_repository_commits,
            fetch_content=fetch_content,
        )
    elif reference.startswith("artifact:"):
        _verify_artifact_reference(
            reference, path, expected_commit=artifact_commit, fetch_run=fetch_run
        )
    else:
        raise EvidenceError(f"{path} must be a phase-bound test or artifact reference")


def _validate_behavior_catalog(
    value: Any,
    *,
    repository: str,
    reviewed_base: str,
    reviewed_head: str,
    trusted_policy_ref: str,
    changed_files: list[Mapping[str, Any]],
    fetch_content: ContentFetcher,
) -> CatalogSelection:
    reference = _parse_catalog_reference(value, "behavior_catalog")
    if (
        reference.repository.casefold() != repository.casefold()
        or reference.commit != reviewed_base
    ):
        raise EvidenceError(
            "behavior_catalog must be in this repository at reviewed_base"
        )
    if not reference.path.startswith(".github/feature-regression/"):
        raise EvidenceError(
            "behavior_catalog must use the reserved .github/feature-regression path"
        )
    catalog = _mapping(
        _parse_strict_json(
            fetch_content(reference.repository, reference.path, reference.commit),
            "behavior catalog",
        ),
        "behavior catalog",
    )
    _validate_sanitized_strings(catalog, "behavior catalog")
    _exact_keys(
        catalog,
        {"schema", "repository", "producer", "operations"},
        "behavior catalog",
    )
    if catalog.get("schema") != "elevenid.behavior-catalog/v3":
        raise EvidenceError("behavior catalog schema is invalid")
    if str(catalog.get("repository", "")).casefold() != repository.casefold():
        raise EvidenceError("behavior catalog repository does not match")
    producer_value = _mapping(catalog.get("producer"), "behavior catalog.producer")
    _exact_keys(
        producer_value,
        {
            "workflow_path",
            "workflow_sha256",
            "central_workflow_sha",
            "harness_path",
            "harness_sha256",
            "subject_path",
            "subject_sha256",
            "subject_runtime",
            "subject_args",
            "subject_env",
            "runtime_image",
            "job_name",
            "produce_step_name",
            "upload_step_name",
            "artifact_name_prefix",
            "observation_path",
        },
        "behavior catalog.producer",
    )
    workflow_path = _relative_path(
        producer_value.get("workflow_path"), "behavior catalog.producer.workflow_path"
    )
    if not workflow_path.startswith(".github/workflows/") or pathlib.PurePosixPath(
        workflow_path
    ).suffix not in {".yml", ".yaml"}:
        raise EvidenceError(
            "behavior catalog producer workflow_path must name a GitHub Actions workflow"
        )
    workflow_sha256 = _text(
        producer_value.get("workflow_sha256"),
        "behavior catalog.producer.workflow_sha256",
    )
    harness_path = _relative_path(
        producer_value.get("harness_path"), "behavior catalog.producer.harness_path"
    )
    if not harness_path.startswith(".github/feature-regression/"):
        raise EvidenceError(
            "behavior catalog producer harness_path must use the reserved governance path"
        )
    harness_sha256 = _text(
        producer_value.get("harness_sha256"),
        "behavior catalog.producer.harness_sha256",
    )
    subject_path = _relative_path(
        producer_value.get("subject_path"), "behavior catalog.producer.subject_path"
    )
    if not subject_path.startswith(".github/feature-regression/"):
        raise EvidenceError(
            "behavior catalog producer subject_path must use the reserved governance path"
        )
    subject_sha256 = _text(
        producer_value.get("subject_sha256"),
        "behavior catalog.producer.subject_sha256",
    )
    if not all(
        DIGEST.fullmatch(value)
        for value in (workflow_sha256, harness_sha256, subject_sha256)
    ):
        raise EvidenceError("behavior catalog producer digests must use sha256")
    subject_runtime = _text(
        producer_value.get("subject_runtime"),
        "behavior catalog.producer.subject_runtime",
    )
    if subject_runtime not in {"python", "direct"}:
        raise EvidenceError("behavior catalog producer subject_runtime is invalid")
    subject_args = tuple(
        _text(item, "behavior catalog.producer.subject_args")
        for item in _list(
            producer_value.get("subject_args"),
            "behavior catalog.producer.subject_args",
        )
    )
    if any(
        re.fullmatch(r"[A-Za-z0-9_./:=+\-]{1,128}", item) is None
        for item in subject_args
    ):
        raise EvidenceError("behavior catalog producer subject_args are invalid")
    subject_env_value = _mapping(
        producer_value.get("subject_env"), "behavior catalog.producer.subject_env"
    )
    subject_env: dict[str, str] = {}
    for name, raw_value in subject_env_value.items():
        value = _text(raw_value, f"behavior catalog.producer.subject_env.{name}")
        if (
            re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name) is None
            or name in {"LC_ALL", "PYTHONHASHSEED", "TZ"}
            or re.fullmatch(r"[A-Za-z0-9_./:=+\-]{0,256}", value) is None
        ):
            raise EvidenceError("behavior catalog producer subject_env is invalid")
        subject_env[name] = value
    runtime_image = _text(
        producer_value.get("runtime_image"),
        "behavior catalog.producer.runtime_image",
    )
    if OCI_IMAGE.fullmatch(runtime_image) is None:
        raise EvidenceError(
            "behavior catalog producer runtime_image must be pinned by sha256 digest"
        )
    central_workflow_sha = _sha(
        producer_value.get("central_workflow_sha"),
        "behavior catalog.producer.central_workflow_sha",
    )
    if central_workflow_sha != trusted_policy_ref:
        raise EvidenceError(
            "behavior catalog central workflow SHA must match the trusted policy ref"
        )
    job_name = _text(
        producer_value.get("job_name"), "behavior catalog.producer.job_name"
    )
    produce_step_name = _text(
        producer_value.get("produce_step_name"),
        "behavior catalog.producer.produce_step_name",
    )
    upload_step_name = _text(
        producer_value.get("upload_step_name"),
        "behavior catalog.producer.upload_step_name",
    )
    artifact_name_prefix = _text(
        producer_value.get("artifact_name_prefix"),
        "behavior catalog.producer.artifact_name_prefix",
    )
    for field, text_value in (
        ("job_name", job_name),
        ("produce_step_name", produce_step_name),
        ("upload_step_name", upload_step_name),
    ):
        if not re.fullmatch(r"[A-Za-z0-9_./ -]{1,100}", text_value):
            raise EvidenceError(f"behavior catalog producer {field} is invalid")
    if produce_step_name == upload_step_name:
        raise EvidenceError("behavior catalog producer step names must be distinct")
    if (
        produce_step_name != ATOMIC_PRODUCE_STEP_NAME
        or upload_step_name != UPLOAD_OBSERVATIONS_STEP_NAME
    ):
        raise EvidenceError(
            "behavior catalog producer step names must identify the atomic producer "
            "and upload steps"
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,70}", artifact_name_prefix):
        raise EvidenceError("behavior catalog producer artifact_name_prefix is invalid")
    observation_path = _relative_path(
        producer_value.get("observation_path"),
        "behavior catalog.producer.observation_path",
    )
    if pathlib.PurePosixPath(observation_path).suffix != ".json":
        raise EvidenceError("behavior catalog producer observation_path must be JSON")
    producer = ProducerContract(
        workflow_path=workflow_path,
        workflow_sha256=workflow_sha256,
        central_workflow_sha=central_workflow_sha,
        harness_path=harness_path,
        harness_sha256=harness_sha256,
        subject_path=subject_path,
        subject_sha256=subject_sha256,
        subject_runtime=subject_runtime,
        subject_args=subject_args,
        subject_env=subject_env,
        runtime_image=runtime_image,
        job_name=job_name,
        produce_step_name=produce_step_name,
        upload_step_name=upload_step_name,
        artifact_name_prefix=artifact_name_prefix,
        observation_path=observation_path,
    )
    base_workflow = fetch_content(repository, workflow_path, reviewed_base)
    head_workflow = fetch_content(repository, workflow_path, reviewed_head)
    if base_workflow != head_workflow:
        raise EvidenceError("producer workflow must be byte-identical at base and head")
    if _raw_sha256(base_workflow) != workflow_sha256:
        raise EvidenceError("producer workflow does not match the catalog digest")
    if base_workflow != _expected_producer_workflow(producer):
        raise EvidenceError(
            "producer workflow is not the exact pinned central reusable caller"
        )
    base_harness = fetch_content(repository, harness_path, reviewed_base)
    head_harness = fetch_content(repository, harness_path, reviewed_head)
    if base_harness != head_harness:
        raise EvidenceError(
            "observation harness must be byte-identical at base and head"
        )
    if _raw_sha256(base_harness) != harness_sha256:
        raise EvidenceError("observation harness does not match the catalog digest")
    base_subject = fetch_content(repository, subject_path, reviewed_base)
    head_subject = fetch_content(repository, subject_path, reviewed_head)
    if base_subject != head_subject:
        raise EvidenceError(
            "observation subject must be byte-identical at base and head"
        )
    if _raw_sha256(base_subject) != subject_sha256:
        raise EvidenceError("observation subject does not match the catalog digest")
    cases: dict[str, tuple[str, str, set[str]]] = {}
    components: list[tuple[str, str]] = []
    operation_ids: set[str] = set()
    for operation_index, raw_operation in enumerate(
        _list(catalog.get("operations"), "behavior catalog.operations")
    ):
        operation_path = f"behavior catalog.operations[{operation_index}]"
        operation = _mapping(raw_operation, operation_path)
        _exact_keys(operation, {"id", "name", "cases"}, operation_path)
        operation_id = _text(operation.get("id"), f"{operation_path}.id")
        operation_name = _text(operation.get("name"), f"{operation_path}.name")
        if operation_id in operation_ids:
            raise EvidenceError("behavior catalog operation ids must be unique")
        operation_ids.add(operation_id)
        for case_index, raw_case in enumerate(
            _list(operation.get("cases"), f"{operation_path}.cases")
        ):
            case_path = f"{operation_path}.cases[{case_index}]"
            case = _mapping(raw_case, case_path)
            _exact_keys(case, {"id", "components", "invariants"}, case_path)
            case_id = _text(case.get("id"), f"{case_path}.id")
            if case_id in cases:
                raise EvidenceError("behavior catalog case ids must be unique")
            invariants = {
                _text(item, f"{case_path}.invariants")
                for item in _list(case.get("invariants"), f"{case_path}.invariants")
            }
            expected_invariants = {
                "public_status",
                "public_message",
                "safe_server_diagnostic",
            }
            if invariants != expected_invariants:
                raise EvidenceError(
                    f"{case_path}.invariants must contain the exact operation triple"
                )
            for component in _list(case.get("components"), f"{case_path}.components"):
                components.append(
                    (_relative_path(component, f"{case_path}.components"), case_id)
                )
            cases[case_id] = (operation_id, operation_name, invariants)
    required_cases: set[str] = set()
    for index, changed_file in enumerate(changed_files):
        item = _mapping(changed_file, f"files[{index}]")
        paths = [item.get("filename")]
        if item.get("previous_filename"):
            paths.append(item.get("previous_filename"))
        for raw_path in paths:
            changed_path = _relative_path(raw_path, f"files[{index}].path")
            if _is_test_path(changed_path) or _is_obvious_docs_path(changed_path):
                continue
            matched = {
                case_id
                for component, case_id in components
                if changed_path == component or changed_path.startswith(component + "/")
            }
            if not matched:
                raise EvidenceError(
                    f"production path {changed_path} is unmapped in the base behavior catalog"
                )
            required_cases.update(matched)
    if not required_cases:
        raise EvidenceError("applicable production change derives no catalog cases")
    return CatalogSelection(
        cases={case_id: cases[case_id] for case_id in required_cases},
        producer=producer,
    )


def _select_observation(
    document: Mapping[str, Any],
    *,
    path: str,
    observation_id: str,
    expected_repository: str,
    expected_revision: str,
    expected_phase: str,
    operation_id: str,
    case_id: str,
    dimension: str,
    expected_value: Any,
    record_fields: set[str],
) -> Mapping[str, Any]:
    _validate_sanitized_strings(document, f"{path} observation document")
    expected_document_fields = {
        "schema",
        "repository",
        "revision",
        "phase",
        "observations",
    }
    expected_document_fields.update({"producer", "runtime_receipt"})
    _exact_keys(document, expected_document_fields, f"{path} observation document")
    if document.get("schema") != "elevenid.behavior-observations/v3":
        raise EvidenceError(f"{path} observation schema is invalid")
    if (
        str(document.get("repository", "")).casefold() != expected_repository.casefold()
        or document.get("revision") != expected_revision
        or document.get("phase") != expected_phase
    ):
        raise EvidenceError(f"{path} observation phase metadata does not match")
    receipt = _mapping(
        document.get("runtime_receipt"), f"{path} observation runtime_receipt"
    )
    _exact_keys(
        receipt,
        {
            "runtime_image",
            "subject_path",
            "subject_sha256",
            "runtime",
            "arguments",
            "environment",
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
        },
        f"{path} observation runtime_receipt",
    )
    _relative_path(
        receipt.get("subject_path"),
        f"{path} observation runtime_receipt.subject_path",
    )
    if OCI_IMAGE.fullmatch(str(receipt.get("runtime_image"))) is None:
        raise EvidenceError(
            f"{path} observation runtime_receipt runtime_image is invalid"
        )
    for field in ("subject_sha256", "stdout_sha256", "stderr_sha256"):
        if DIGEST.fullmatch(str(receipt.get(field))) is None:
            raise EvidenceError(
                f"{path} observation runtime_receipt {field} is invalid"
            )
    if (
        receipt.get("runtime") not in {"python", "direct"}
        or receipt.get("exit_code") != 0
    ):
        raise EvidenceError(
            f"{path} observation runtime_receipt must record a successful invocation"
        )
    _list(receipt.get("arguments"), f"{path} observation runtime_receipt.arguments")
    _mapping(
        receipt.get("environment"),
        f"{path} observation runtime_receipt.environment",
    )
    matches: list[Mapping[str, Any]] = []
    observation_ids: set[str] = set()
    for index, raw_observation in enumerate(
        _list(document.get("observations"), f"{path} observations")
    ):
        observation_path = f"{path} observations[{index}]"
        observation = _mapping(raw_observation, observation_path)
        _exact_keys(observation, record_fields, observation_path)
        record_id = _text(observation.get("id"), f"{observation_path}.id")
        if record_id in observation_ids:
            raise EvidenceError(f"{path} observation ids must be unique")
        observation_ids.add(record_id)
        if record_id == observation_id:
            matches.append(observation)
    if len(matches) != 1:
        raise EvidenceError(f"{path} must select exactly one observation")
    observation = matches[0]
    expected = {
        "operation_id": operation_id,
        "case_id": case_id,
        "dimension": dimension,
    }
    for field, expected_field in expected.items():
        if observation.get(field) != expected_field:
            raise EvidenceError(f"{path} observation {field} does not match")
    if _deterministic_json_bytes(observation.get("value")) != _deterministic_json_bytes(
        expected_value
    ):
        raise EvidenceError(f"{path} observation value does not match exact evidence")
    return observation


def _artifact_observation_bytes(
    archive: bytes, *, member_path: str, path: str
) -> bytes:
    if not archive or len(archive) > MAX_ARTIFACT_BYTES:
        raise EvidenceError(f"{path} artifact archive size is unsafe")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            members = bundle.infolist()
            if len(members) != 1:
                raise EvidenceError(f"{path} artifact must contain exactly one file")
            member = members[0]
            normalized = member.filename.replace("\\", "/")
            pure_path = pathlib.PurePosixPath(normalized)
            unix_mode = member.external_attr >> 16
            file_type = unix_mode & 0o170000
            if (
                member.is_dir()
                or normalized != member_path
                or normalized.startswith("/")
                or any(part in {"", ".", ".."} for part in pure_path.parts)
                or file_type not in {0, 0o100000}
                or member.flag_bits & 0x1
                or member.file_size > MAX_OBSERVATION_BYTES
            ):
                raise EvidenceError(f"{path} artifact ZIP topology is unsafe")
            payload = bundle.read(member)
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        raise EvidenceError(f"{path} artifact is not a valid safe ZIP") from error
    if len(payload) != member.file_size:
        raise EvidenceError(f"{path} artifact observation size does not match")
    return payload


def _validate_artifact_observation(
    value: Any,
    path: str,
    *,
    expected_repository: str,
    expected_commit: str,
    expected_phase: str,
    producer: ProducerContract,
    operation_id: str,
    case_id: str,
    dimension: str,
    expected_value: Any,
    fetch_content: ContentFetcher,
    fetch_run: RunFetcher,
    fetch_jobs: JobsFetcher,
    fetch_artifacts: ArtifactsFetcher,
    download_artifact: ArtifactDownloader,
) -> None:
    reference = _parse_artifact_observation_reference(value, path)
    if reference.repository.casefold() != expected_repository.casefold():
        raise EvidenceError(f"{path} artifact repository does not match")
    run = _mapping(
        fetch_run(reference.repository, reference.run_id), f"{path} Actions run"
    )
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise EvidenceError(f"{path} Actions run must be completed successfully")
    if _sha(run.get("head_sha"), f"{path} Actions run head") != expected_commit:
        reviewed_label = (
            "reviewed_base" if expected_phase == "before" else "reviewed_head"
        )
        raise EvidenceError(
            f"{path} Actions run must bind the exact {reviewed_label} commit"
        )
    event_name = _text(run.get("event"), f"{path} Actions run event")
    head_branch = _text(run.get("head_branch"), f"{path} Actions run head_branch")
    if expected_phase == "after":
        if event_name != "pull_request":
            raise EvidenceError(
                f"{path} after artifact must come from a pull_request run"
            )
    elif (
        event_name not in {"push", "schedule", "workflow_dispatch"}
        or head_branch != "main"
    ):
        raise EvidenceError(
            f"{path} before artifact must come from push, schedule, or "
            "workflow_dispatch on main"
        )
    run_attempt = run.get("run_attempt")
    if not isinstance(run_attempt, int) or run_attempt <= 0:
        raise EvidenceError(f"{path} Actions run_attempt must be positive")
    run_path = _text(run.get("path"), f"{path} Actions run path").split("@", 1)[0]
    if run_path != producer.workflow_path:
        raise EvidenceError(f"{path} Actions run workflow does not match the catalog")
    matching_jobs = [
        job
        for job in fetch_jobs(reference.repository, reference.run_id, run_attempt)
        if job.get("name") == producer.job_name
    ]
    if len(matching_jobs) != 1:
        raise EvidenceError(f"{path} catalog producer job must be unique")
    job = _mapping(matching_jobs[0], f"{path} producer job")
    if (
        job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or job.get("run_id") != reference.run_id
        or _sha(job.get("head_sha"), f"{path} producer job head") != expected_commit
        or ("run_attempt" in job and job.get("run_attempt") != run_attempt)
    ):
        raise EvidenceError(f"{path} catalog producer job must succeed in this attempt")
    steps = _list(job.get("steps"), f"{path} producer job steps")
    for required_name in (
        producer.produce_step_name,
        producer.upload_step_name,
    ):
        matches = [
            _mapping(step, f"{path} producer job step")
            for step in steps
            if isinstance(step, Mapping) and step.get("name") == required_name
        ]
        if len(matches) != 1:
            raise EvidenceError(
                f"{path} required producer step {required_name!r} must be unique"
            )
        step = matches[0]
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            raise EvidenceError(
                f"{path} required producer step {required_name!r} must succeed"
            )
    artifact_name = f"{producer.artifact_name_prefix}-{reference.run_id}-{run_attempt}"
    matching_artifacts = [
        artifact
        for artifact in fetch_artifacts(reference.repository, reference.run_id)
        if artifact.get("name") == artifact_name
    ]
    if len(matching_artifacts) != 1:
        raise EvidenceError(f"{path} catalog producer artifact must be unique")
    artifact = _mapping(matching_artifacts[0], f"{path} producer artifact")
    artifact_id = artifact.get("id")
    if not isinstance(artifact_id, int) or artifact_id <= 0:
        raise EvidenceError(f"{path} artifact id must be positive")
    if artifact.get("expired") is not False:
        raise EvidenceError(f"{path} artifact must be unexpired")
    workflow_run = _mapping(
        artifact.get("workflow_run"), f"{path} artifact workflow_run"
    )
    if workflow_run.get("id") != reference.run_id:
        raise EvidenceError(f"{path} artifact workflow_run id does not match")
    if (
        _sha(workflow_run.get("head_sha"), f"{path} artifact workflow_run head")
        != expected_commit
    ):
        raise EvidenceError(f"{path} artifact workflow_run head does not match")
    if (
        _text(
            workflow_run.get("head_branch"),
            f"{path} artifact workflow_run head_branch",
        )
        != head_branch
    ):
        raise EvidenceError(
            f"{path} artifact workflow_run head_branch does not match the Actions run"
        )
    expected_repository_id = _mapping(
        run.get("repository"), f"{path} run repository"
    ).get("id")
    expected_head_repository_id = _mapping(
        run.get("head_repository"), f"{path} run head_repository"
    ).get("id")
    for field, expected_id in (
        ("repository_id", expected_repository_id),
        ("head_repository_id", expected_head_repository_id),
    ):
        if (
            not isinstance(expected_id, int)
            or not isinstance(workflow_run.get(field), int)
            or workflow_run.get(field) != expected_id
        ):
            raise EvidenceError(f"{path} artifact workflow_run {field} does not match")
    digest = _text(artifact.get("digest"), f"{path} artifact digest")
    if not DIGEST.fullmatch(digest):
        raise EvidenceError(f"{path} artifact digest must be an API sha256 digest")
    archive = download_artifact(reference.repository, artifact_id)
    actual_digest = f"sha256:{hashlib.sha256(archive).hexdigest()}"
    if actual_digest != digest:
        raise EvidenceError(
            f"{path} downloaded artifact digest does not match API metadata"
        )
    payload = _artifact_observation_bytes(
        archive, member_path=producer.observation_path, path=path
    )
    document = _mapping(
        _parse_strict_json(payload, f"{path} artifact observation document"),
        f"{path} artifact observation document",
    )
    if payload != _deterministic_json_bytes(document):
        raise EvidenceError(f"{path} artifact observation JSON must be canonical")
    provenance = _mapping(document.get("producer"), f"{path} observation producer")
    _exact_keys(
        provenance,
        {
            "workflow_path",
            "workflow_sha256",
            "central_workflow_sha",
            "harness_path",
            "harness_sha256",
            "subject_path",
            "subject_sha256",
            "subject_runtime",
            "subject_args",
            "subject_env",
            "runtime_image",
            "job_name",
            "artifact_name",
            "run_id",
            "run_attempt",
            "head_sha",
            "phase",
            "event_name",
            "head_branch",
        },
        f"{path} observation producer",
    )
    expected_provenance = {
        "workflow_path": producer.workflow_path,
        "workflow_sha256": producer.workflow_sha256,
        "central_workflow_sha": producer.central_workflow_sha,
        "harness_path": producer.harness_path,
        "harness_sha256": producer.harness_sha256,
        "subject_path": producer.subject_path,
        "subject_sha256": producer.subject_sha256,
        "subject_runtime": producer.subject_runtime,
        "subject_args": list(producer.subject_args),
        "subject_env": producer.subject_env,
        "runtime_image": producer.runtime_image,
        "job_name": producer.job_name,
        "artifact_name": artifact_name,
        "run_id": reference.run_id,
        "run_attempt": run_attempt,
        "head_sha": expected_commit,
        "phase": expected_phase,
        "event_name": event_name,
        "head_branch": head_branch,
    }
    if dict(provenance) != expected_provenance:
        raise EvidenceError(
            f"{path} artifact provenance does not match the run/catalog"
        )
    receipt = _mapping(
        document.get("runtime_receipt"), f"{path} observation runtime_receipt"
    )
    expected_environment = {
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        **producer.subject_env,
    }
    for field, expected_receipt_value in (
        ("runtime_image", producer.runtime_image),
        ("subject_path", producer.subject_path),
        ("subject_sha256", producer.subject_sha256),
        ("runtime", producer.subject_runtime),
        ("arguments", list(producer.subject_args)),
        ("environment", expected_environment),
        ("exit_code", 0),
    ):
        if receipt.get(field) != expected_receipt_value:
            raise EvidenceError(
                f"{path} runtime receipt {field} does not match the catalog"
            )
    observation = _select_observation(
        document,
        path=path,
        observation_id=reference.observation_id,
        expected_repository=expected_repository,
        expected_revision=expected_commit,
        expected_phase=expected_phase,
        operation_id=operation_id,
        case_id=case_id,
        dimension=dimension,
        expected_value=expected_value,
        record_fields={
            "id",
            "operation_id",
            "case_id",
            "dimension",
            "value",
            "producer_test",
        },
    )
    _verify_test_reference(
        observation.get("producer_test"),
        f"{path} observation producer_test",
        allowed_repository_commits={(expected_repository.casefold(), expected_commit)},
        fetch_content=fetch_content,
    )


def _validate_phase_bound_evidence(
    document: Mapping[str, Any],
    *,
    repository: str,
    reviewed_base: str,
    reviewed_head: str,
    inventory_sources: list[InventorySource],
    catalog: CatalogSelection | None,
    fetch_content: ContentFetcher,
    fetch_run: RunFetcher,
    fetch_jobs: JobsFetcher,
    fetch_artifacts: ArtifactsFetcher,
    download_artifact: ArtifactDownloader,
) -> None:
    current_repository = repository.casefold()
    phase_sources = {
        phase: {
            source.normalized_content_tuple
            for source in inventory_sources
            if source.phase == phase
        }
        for phase in ("pre_change", "post_change")
    }
    required_cases = catalog.cases if catalog is not None else {}
    evidenced_cases: set[str] = set()
    for operation_index, raw_operation in enumerate(
        _list(document.get("operations"), "operations")
    ):
        path = f"operations[{operation_index}]"
        operation = _mapping(raw_operation, path)
        operation_id = _text(operation.get("id"), f"{path}.id")
        case_id = _text(operation.get("case_id"), f"{path}.case_id")
        operation_name = _text(operation.get("name"), f"{path}.name")
        catalog_case = required_cases.get(case_id)
        if catalog_case is None:
            raise EvidenceError(f"{path}.case_id is not derived from changed paths")
        if (operation_id, operation_name) != catalog_case[:2]:
            raise EvidenceError(f"{path} does not match the base behavior catalog")
        if case_id in evidenced_cases:
            raise EvidenceError("operations may evidence each catalog case only once")
        evidenced_cases.add(case_id)
        for dimension in (
            "public_status",
            "public_message",
            "safe_server_diagnostic",
        ):
            comparison = _mapping(operation.get(dimension), f"{path}.{dimension}")
            if comparison.get("disposition") == "not_applicable":
                continue
            for phase in ("before", "after"):
                snapshot = _mapping(
                    comparison.get(phase), f"{path}.{dimension}.{phase}"
                )
                references = _list(
                    snapshot.get("evidence"),
                    f"{path}.{dimension}.{phase}.evidence",
                )
                if not references:
                    raise EvidenceError("observation evidence must not be empty")
                for reference_index, reference in enumerate(references):
                    reference_path = (
                        f"{path}.{dimension}.{phase}.evidence[{reference_index}]"
                    )
                    if not str(reference).startswith("artifact-observation:"):
                        raise EvidenceError(
                            f"{path}.{dimension}.{phase}.evidence must use downloaded "
                            "artifact observations"
                        )
                    _validate_artifact_observation(
                        reference,
                        reference_path,
                        expected_repository=repository,
                        expected_commit=(
                            reviewed_base if phase == "before" else reviewed_head
                        ),
                        expected_phase=phase,
                        producer=catalog.producer,
                        operation_id=operation_id,
                        case_id=case_id,
                        dimension=dimension,
                        expected_value=snapshot.get("value"),
                        fetch_content=fetch_content,
                        fetch_run=fetch_run,
                        fetch_jobs=fetch_jobs,
                        fetch_artifacts=fetch_artifacts,
                        download_artifact=download_artifact,
                    )
            if comparison.get("disposition") == "moved":
                mapping = _mapping(
                    comparison.get("test_mapping"), f"{path}.{dimension}.test_mapping"
                )
                _verify_test_reference(
                    mapping.get("before"),
                    f"{path}.{dimension}.test_mapping.before",
                    allowed_repository_commits={(current_repository, reviewed_base)},
                    allowed_exact_sources=phase_sources["pre_change"],
                    fetch_content=fetch_content,
                )
                _verify_test_reference(
                    mapping.get("after"),
                    f"{path}.{dimension}.test_mapping.after",
                    allowed_repository_commits={(current_repository, reviewed_head)},
                    allowed_exact_sources=phase_sources["post_change"],
                    fetch_content=fetch_content,
                )
    if evidenced_cases != set(required_cases):
        raise EvidenceError("operations do not cover every changed-path catalog case")

    for index, reference in enumerate(_list(document.get("tests"), "tests")):
        _verify_test_reference(
            reference,
            f"tests[{index}]",
            allowed_repository_commits={(current_repository, reviewed_head)},
            fetch_content=fetch_content,
        )
    for collection_name in ("findings", "behavior_dispositions"):
        for item_index, raw_item in enumerate(
            _list(document.get(collection_name), collection_name)
        ):
            item = _mapping(raw_item, f"{collection_name}[{item_index}]")
            for reference_index, reference in enumerate(
                _list(item.get("evidence"), f"{collection_name}[{item_index}].evidence")
            ):
                _verify_raw_reference(
                    reference,
                    f"{collection_name}[{item_index}].evidence[{reference_index}]",
                    allowed_test_repository_commits={
                        (current_repository, reviewed_head)
                    },
                    artifact_commit=reviewed_head,
                    fetch_content=fetch_content,
                    fetch_run=fetch_run,
                )
            if item.get("disposition") == "moved":
                mapping = _mapping(
                    item.get("test_mapping"),
                    f"{collection_name}[{item_index}].test_mapping",
                )
                _verify_test_reference(
                    mapping.get("before"),
                    f"{collection_name}[{item_index}].test_mapping.before",
                    allowed_repository_commits={(current_repository, reviewed_base)},
                    allowed_exact_sources=phase_sources["pre_change"],
                    fetch_content=fetch_content,
                )
                _verify_test_reference(
                    mapping.get("after"),
                    f"{collection_name}[{item_index}].test_mapping.after",
                    allowed_repository_commits={(current_repository, reviewed_head)},
                    allowed_exact_sources=phase_sources["post_change"],
                    fetch_content=fetch_content,
                )
    for surface, coverage in _mapping(
        document.get("surface_coverage"), "surface_coverage"
    ).items():
        coverage = _mapping(coverage, f"surface_coverage.{surface}")
        if "evidence" not in coverage:
            continue
        references = _list(
            coverage.get("evidence"), f"surface_coverage.{surface}.evidence"
        )
        if surface == "production_boundary_tests_demos" and not any(
            str(reference).startswith("artifact:") for reference in references
        ):
            raise EvidenceError(
                "production_boundary_tests_demos must include a successful head artifact"
            )
        for index, reference in enumerate(references):
            _verify_raw_reference(
                reference,
                f"surface_coverage.{surface}.evidence[{index}]",
                allowed_test_repository_commits={(current_repository, reviewed_head)},
                artifact_commit=reviewed_head,
                fetch_content=fetch_content,
                fetch_run=fetch_run,
            )


def _is_test_path(path: str) -> bool:
    parts = path.casefold().split("/")
    name = parts[-1]
    stem = name.rsplit(".", 1)[0]
    return (
        any(part in {"test", "tests", "__tests__"} for part in parts[:-1])
        or name.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec"))
    )


def _is_obvious_docs_path(path: str) -> bool:
    normalized = path.casefold()
    parts = normalized.split("/")
    name = parts[-1]
    suffix = "." + name.rsplit(".", 1)[1] if "." in name else ""
    if any(token in PRODUCTION_TOKENS for token in parts):
        return False
    if any(
        token in name
        for token in ("contract", "schema", "openapi", "asyncapi", "migration")
    ):
        return False
    if len(parts) == 1 and name in ROOT_DOCS:
        return True
    return parts[0] in {"docs", "documentation"} and suffix in DOC_EXTENSIONS


def classify_changed_files(files: Iterable[Mapping[str, Any]]) -> tuple[str, str]:
    changed = list(files)
    if not changed:
        return "uncertain", "GitHub returned no changed files"
    for index, value in enumerate(changed):
        item = _mapping(value, f"files[{index}]")
        path = _relative_path(item.get("filename"), f"files[{index}].filename")
        status = _text(item.get("status"), f"files[{index}].status")
        if status in {"removed", "renamed"} or item.get("previous_filename"):
            return "production", f"{path} is deleted or renamed"
        if status not in {"added", "modified", "changed", "copied"}:
            return "uncertain", f"{path} has unknown status {status!r}"
        if path.casefold().startswith(".github/feature-regression/"):
            return "production", f"{path} is reserved feature-regression governance"
        if _is_test_path(path) or _is_obvious_docs_path(path):
            continue
        parts = path.casefold().split("/")
        name = parts[-1]
        suffix = "." + name.rsplit(".", 1)[1] if "." in name else ""
        if any(part in PRODUCTION_TOKENS for part in parts):
            return "production", f"{path} is source/config/contract/deploy/workflow"
        if suffix in PRODUCTION_EXTENSIONS or name in PRODUCTION_FILENAMES:
            return "production", f"{path} is executable source or configuration"
        return "uncertain", f"{path} is not an obvious documentation or test file"
    return "docs_tests_only", "all files are obvious documentation or tests"


def validate_evidence(
    evidence: Any,
    *,
    repository: str,
    current_base: str,
    current_head: str,
    trusted_policy_ref: str,
    comment_author: str,
    comment_author_association: str,
    changed_files: Iterable[Mapping[str, Any]],
    fetch_content: ContentFetcher,
    fetch_run: RunFetcher,
    fetch_jobs: JobsFetcher,
    fetch_artifacts: ArtifactsFetcher,
    download_artifact: ArtifactDownloader,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> Mapping[str, Any]:
    document = _mapping(evidence, "evidence")
    _validate_sanitized_strings(document)
    _exact_keys(document, TOP_LEVEL_FIELDS, "evidence")
    if document.get("schema") != SCHEMA:
        raise EvidenceError(f"schema must equal {SCHEMA!r}")
    reviewed_repository = _repository(document.get("repository"), "repository")
    if reviewed_repository.casefold() != repository.casefold():
        raise EvidenceError("repository does not match the current repository")
    reviewed_base = _sha(document.get("reviewed_base"), "reviewed_base")
    if reviewed_base != current_base:
        raise EvidenceError(
            f"reviewed_base {reviewed_base} does not match actual base {current_base}"
        )
    reviewed_head = _sha(document.get("reviewed_head"), "reviewed_head")
    if reviewed_head != current_head:
        raise EvidenceError(
            f"reviewed_head {reviewed_head} does not match current PR head {current_head}"
        )
    trusted_policy_ref = _sha(trusted_policy_ref, "trusted_policy_ref")

    association = _text(
        comment_author_association, "comment.author_association"
    ).upper()
    if association not in AUTHORITY_ASSOCIATIONS:
        raise EvidenceError(
            "evidence commenter must be an OWNER, MEMBER, or COLLABORATOR"
        )
    reviewer = _mapping(document.get("reviewer"), "reviewer")
    _exact_keys(reviewer, {"login", "role", "context"}, "reviewer")
    reviewer_login = _text(reviewer.get("login"), "reviewer.login")
    if reviewer_login.casefold() != comment_author.casefold():
        raise EvidenceError("reviewer.login must match the evidence comment author")
    if reviewer.get("role") != "feature_regression_reviewer":
        raise EvidenceError("reviewer.role must equal 'feature_regression_reviewer'")
    reviewer_context = _text(reviewer.get("context"), "reviewer.context")
    implementation_context = _text(
        document.get("implementation_context"), "implementation_context"
    )
    if reviewer_context.casefold() == implementation_context.casefold():
        raise EvidenceError(
            "reviewer.context must be distinct from implementation_context"
        )

    applicability = _mapping(document.get("applicability"), "applicability")
    _exact_keys(applicability, {"decision", "rationale"}, "applicability")
    decision = _text(applicability.get("decision"), "applicability.decision")
    if decision not in {"applicable", "not_applicable"}:
        raise EvidenceError(
            "applicability.decision must be 'applicable' or 'not_applicable'"
        )
    _text(applicability.get("rationale"), "applicability.rationale")
    changed_files = list(changed_files)
    classification, reason = classify_changed_files(changed_files)
    if decision == "not_applicable" and classification != "docs_tests_only":
        raise EvidenceError(
            f"not_applicable is forbidden for this change: {classification}: {reason}"
        )

    if not _bool(
        document.get("sanitized_public_evidence"), "sanitized_public_evidence"
    ):
        raise EvidenceError("sanitized_public_evidence must be true")
    inventory_sources = _validate_inventory_sources(document.get("inventory_sources"))
    for inventory_source in inventory_sources:
        fetch_content(*inventory_source.content_tuple)
    _validate_findings(document.get("findings"))
    _validate_commands(document.get("commands"))
    _test_references(document.get("tests"), "tests")
    _validate_named_rationales(
        document.get("unexercised_surfaces"), "unexercised_surfaces"
    )
    _validate_residual_risks(document.get("residual_risks"))
    production_affecting = (
        decision == "applicable" and classification != "docs_tests_only"
    )
    _validate_surface_coverage(
        document.get("surface_coverage"),
        allow_not_applicable=not production_affecting,
    )

    operations = document.get("operations")
    dispositions = document.get("behavior_dispositions")
    if decision == "not_applicable":
        if operations != [] or dispositions != []:
            raise EvidenceError(
                "not_applicable evidence must use empty operations and "
                "behavior_dispositions arrays"
            )
    else:
        _validate_operations(
            operations,
            reviewer_login=reviewer_login,
            repository=reviewed_repository,
            reviewed_base=reviewed_base,
            allow_not_applicable=not production_affecting,
            authority_resolver=authority_resolver,
            decision_fetcher=decision_fetcher,
        )
        _validate_behavior_dispositions(
            dispositions,
            reviewer_login=reviewer_login,
            repository=reviewed_repository,
            reviewed_base=reviewed_base,
            authority_resolver=authority_resolver,
            decision_fetcher=decision_fetcher,
        )
    external_moved_owners = _external_moved_owners(
        document, current_repository=reviewed_repository
    )
    inventory_repositories = {
        source.repository.casefold() for source in inventory_sources
    }
    cross_required = (
        len(inventory_repositories) > 1
        or any(
            source_repository != reviewed_repository.casefold()
            for source_repository in inventory_repositories
        )
        or bool(external_moved_owners)
    )
    _validate_cross_boundary(
        document.get("cross_boundary"),
        fetch_content=fetch_content,
        inventory_sources=inventory_sources,
        current_repository=reviewed_repository,
        reviewed_head=reviewed_head,
        required=cross_required,
        external_moved_owners=external_moved_owners,
    )
    if production_affecting:
        catalog = _validate_behavior_catalog(
            document.get("behavior_catalog"),
            repository=reviewed_repository,
            reviewed_base=reviewed_base,
            reviewed_head=reviewed_head,
            trusted_policy_ref=trusted_policy_ref,
            changed_files=changed_files,
            fetch_content=fetch_content,
        )
    else:
        if document.get("behavior_catalog") is not None:
            raise EvidenceError(
                "behavior_catalog must be null when no production catalog applies"
            )
        catalog = None
    _validate_phase_bound_evidence(
        document,
        repository=reviewed_repository,
        reviewed_base=reviewed_base,
        reviewed_head=reviewed_head,
        inventory_sources=inventory_sources,
        catalog=catalog,
        fetch_content=fetch_content,
        fetch_run=fetch_run,
        fetch_jobs=fetch_jobs,
        fetch_artifacts=fetch_artifacts,
        download_artifact=download_artifact,
    )
    return document


def extract_evidence(body: str) -> Any:
    marker_index = body.find(MARKER)
    if marker_index < 0:
        raise EvidenceError("feature-regression marker is missing")
    remainder = body[marker_index + len(MARKER) :]
    fence = re.search(r"```json\s*\n(?P<payload>.*?)\n```", remainder, re.DOTALL)
    if fence is None:
        raise EvidenceError("marker must be followed by a fenced json document")
    try:
        return json.loads(
            fence.group("payload"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, EvidenceError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError(f"evidence JSON is invalid: {error.msg}") from error


def marked_comments(comments: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    marked: list[Mapping[str, Any]] = []
    for index, value in enumerate(comments):
        comment = _mapping(value, f"comments[{index}]")
        if MARKER in str(comment.get("body", "")):
            marked.append(comment)
    return marked


def validate_latest_comment(
    comments: Iterable[Mapping[str, Any]],
    *,
    repository: str,
    current_base: str,
    current_head: str,
    trusted_policy_ref: str,
    changed_files: Iterable[Mapping[str, Any]],
    fetch_content: ContentFetcher,
    fetch_run: RunFetcher,
    fetch_jobs: JobsFetcher,
    fetch_artifacts: ArtifactsFetcher,
    download_artifact: ArtifactDownloader,
    authority_resolver: AuthorityResolver,
    decision_fetcher: DecisionFetcher,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    candidates = marked_comments(comments)
    if not candidates:
        raise EvidenceError(f"no PR comment contains marker {MARKER}")
    authorized = [
        comment
        for comment in candidates
        if str(comment.get("author_association", "")).upper() in AUTHORITY_ASSOCIATIONS
    ]
    if not authorized:
        raise EvidenceError("no marked PR comment has an authorized commenter")
    comment = authorized[-1]
    user = _mapping(comment.get("user"), "comment.user")
    author = _text(user.get("login"), "comment.user.login")
    association = _text(comment.get("author_association"), "comment.author_association")
    evidence = validate_evidence(
        extract_evidence(str(comment.get("body", ""))),
        repository=repository,
        current_base=current_base,
        current_head=current_head,
        trusted_policy_ref=trusted_policy_ref,
        comment_author=author,
        comment_author_association=association,
        changed_files=changed_files,
        fetch_content=fetch_content,
        fetch_run=fetch_run,
        fetch_jobs=fetch_jobs,
        fetch_artifacts=fetch_artifacts,
        download_artifact=download_artifact,
        authority_resolver=authority_resolver,
        decision_fetcher=decision_fetcher,
    )
    return comment, evidence


class GitHubClient:
    def __init__(self, *, api_url: str, repository: str, token: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.repository = _repository(repository, "repository")
        self.token = _text(token, "GITHUB_TOKEN")

    def _get(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            raise EvidenceError(f"GitHub read failed for {path}: {error}") from error

    def _download_artifact_bytes(self, path: str) -> bytes:
        api_request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        opener = urllib.request.build_opener(_NoRedirect)
        location: str | None = None
        try:
            with opener.open(api_request, timeout=30) as response:
                if response.getcode() != 302:
                    raise EvidenceError(
                        f"GitHub artifact API for {path} did not return one redirect"
                    )
                location = response.headers.get("Location")
        except urllib.error.HTTPError as error:
            if error.code != 302:
                raise EvidenceError(
                    f"GitHub artifact redirect failed for {path}: {error}"
                ) from error
            location = error.headers.get("Location")
        except urllib.error.URLError as error:
            raise EvidenceError(
                f"GitHub artifact redirect failed for {path}: {error}"
            ) from error
        if not location:
            raise EvidenceError(f"GitHub artifact redirect for {path} has no Location")
        parsed = urllib.parse.urlparse(location)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or not parsed.hostname
            or ARTIFACT_STORAGE_HOST.fullmatch(parsed.hostname) is None
        ):
            raise EvidenceError(
                f"GitHub artifact redirect for {path} uses an untrusted storage host"
            )
        storage_request = urllib.request.Request(
            location, headers={"Accept": "application/octet-stream"}
        )
        try:
            with opener.open(storage_request, timeout=30) as response:
                if response.getcode() != 200:
                    raise EvidenceError(
                        f"GitHub artifact storage for {path} did not return 200"
                    )
                payload = response.read(MAX_ARTIFACT_BYTES + 1)
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            raise EvidenceError(
                f"GitHub artifact storage download failed for {path}: {error}"
            ) from error
        if len(payload) > MAX_ARTIFACT_BYTES:
            raise EvidenceError(f"GitHub download for {path} exceeds the size limit")
        return payload

    def _pages(self, path: str) -> list[Mapping[str, Any]]:
        values: list[Mapping[str, Any]] = []
        page = 1
        separator = "&" if "?" in path else "?"
        while True:
            payload = self._get(f"{path}{separator}per_page=100&page={page}")
            items = _list(payload, f"GitHub response for {path}")
            for index, item in enumerate(items):
                values.append(_mapping(item, f"GitHub response {path}[{index}]"))
            if len(items) < 100:
                return values
            page += 1

    def pull(self, number: int) -> Mapping[str, Any]:
        return _mapping(
            self._get(f"/repos/{self.repository}/pulls/{number}"),
            f"pull request {number}",
        )

    def comments(self, number: int) -> list[Mapping[str, Any]]:
        return self._pages(f"/repos/{self.repository}/issues/{number}/comments")

    def files(self, number: int) -> list[Mapping[str, Any]]:
        return self._pages(f"/repos/{self.repository}/pulls/{number}/files")

    def associated_pulls(self, commit: str) -> list[Mapping[str, Any]]:
        _sha(commit, "merge_group.head_sha")
        return self._pages(f"/repos/{self.repository}/commits/{commit}/pulls")

    def commits_between(self, base: str, head: str) -> list[str]:
        base = _sha(base, "merge_group.base_sha")
        head = _sha(head, "merge_group.head_sha")
        payload = _mapping(
            self._get(f"/repos/{self.repository}/compare/{base}...{head}"),
            "merge-group comparison",
        )
        commits = _list(payload.get("commits"), "merge-group comparison.commits")
        total = payload.get("total_commits")
        if not isinstance(total, int) or total != len(commits):
            raise EvidenceError(
                "merge-group comparison is truncated or lacks total_commits"
            )
        return [
            _sha(
                _mapping(commit, f"merge-group commit[{index}]").get("sha"),
                f"merge-group commit[{index}].sha",
            )
            for index, commit in enumerate(commits)
        ]

    def content(self, repository: str, path: str, commit: str) -> bytes:
        repository = _repository(repository, "source.repository")
        path = _relative_path(path, "source.path")
        commit = _sha(commit, "source.commit")
        quoted_path = urllib.parse.quote(path, safe="/")
        payload = _mapping(
            self._get(f"/repos/{repository}/contents/{quoted_path}?ref={commit}"),
            f"contents {repository}/{path}@{commit}",
        )
        if payload.get("type") != "file":
            raise EvidenceError(f"contents {repository}/{path}@{commit} is not a file")
        if payload.get("encoding") != "base64" or not isinstance(
            payload.get("content"), str
        ):
            raise EvidenceError(
                f"contents {repository}/{path}@{commit} is not inline base64"
            )
        try:
            encoded = "".join(payload["content"].split())
            return base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise EvidenceError(
                f"contents {repository}/{path}@{commit} has invalid base64"
            ) from error

    def run(self, repository: str, run_id: int) -> Mapping[str, Any]:
        repository = _repository(repository, "Actions run.repository")
        if not isinstance(run_id, int) or run_id <= 0:
            raise EvidenceError("Actions run id must be a positive integer")
        return _mapping(
            self._get(f"/repos/{repository}/actions/runs/{run_id}"),
            f"Actions run {repository}/{run_id}",
        )

    def _run_collection(
        self, repository: str, run_id: int, path: str, key: str
    ) -> list[Mapping[str, Any]]:
        repository = _repository(repository, f"Actions {key}.repository")
        if not isinstance(run_id, int) or run_id <= 0:
            raise EvidenceError("Actions run id must be a positive integer")
        payload = _mapping(
            self._get(f"/repos/{repository}/actions/runs/{run_id}/{path}?per_page=100"),
            f"Actions run {key}",
        )
        values = _list(payload.get(key), f"Actions run {key}.{key}")
        total = payload.get("total_count")
        if not isinstance(total, int) or total != len(values):
            raise EvidenceError(f"Actions run {key} response is truncated")
        return [
            _mapping(value, f"Actions run {key}[{index}]")
            for index, value in enumerate(values)
        ]

    def jobs(
        self, repository: str, run_id: int, run_attempt: int
    ) -> list[Mapping[str, Any]]:
        if not isinstance(run_attempt, int) or run_attempt <= 0:
            raise EvidenceError("Actions run attempt must be a positive integer")
        return self._run_collection(
            repository,
            run_id,
            f"attempts/{run_attempt}/jobs",
            "jobs",
        )

    def artifacts(self, repository: str, run_id: int) -> list[Mapping[str, Any]]:
        return self._run_collection(repository, run_id, "artifacts", "artifacts")

    def download_artifact(self, repository: str, artifact_id: int) -> bytes:
        repository = _repository(repository, "Actions artifact.repository")
        if not isinstance(artifact_id, int) or artifact_id <= 0:
            raise EvidenceError("Actions artifact id must be a positive integer")
        return self._download_artifact_bytes(
            f"/repos/{repository}/actions/artifacts/{artifact_id}/zip"
        )

    def permission(self, login: str) -> Mapping[str, Any]:
        login = _text(login, "approved_by")
        quoted_login = urllib.parse.quote(login, safe="")
        payload = _mapping(
            self._get(
                f"/repos/{self.repository}/collaborators/{quoted_login}/permission"
            ),
            f"collaborator permission for {login}",
        )
        _text(payload.get("permission"), f"permission for {login}")
        _text(payload.get("role_name"), f"role_name for {login}")
        return payload

    def decision(self, url: str) -> bytes:
        reference = _parse_decision_reference(url, "decision_ref")
        return self.content(reference.repository, reference.path, reference.commit)


def _pull_target(
    metadata: Mapping[str, Any], *, base_override: str | None
) -> ReviewTarget:
    number = metadata.get("number")
    if not isinstance(number, int) or number <= 0:
        raise EvidenceError("pull request number must be a positive integer")
    if metadata.get("state") != "open":
        raise EvidenceError(f"pull request {number} must still be open")
    base = _mapping(metadata.get("base"), f"pull request {number}.base")
    head = _mapping(metadata.get("head"), f"pull request {number}.head")
    base_sha = base_override or _sha(base.get("sha"), f"pull request {number}.base.sha")
    return ReviewTarget(
        number=number,
        base_sha=_sha(base_sha, f"pull request {number} reviewed base"),
        head_sha=_sha(head.get("sha"), f"pull request {number}.head.sha"),
    )


def review_targets(event: Any, client: GitHubClient) -> list[ReviewTarget]:
    document = _mapping(event, "event")
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    if "pull_request" in document or event_name == "pull_request":
        number = document.get("number")
        if not isinstance(number, int) or number <= 0:
            raise EvidenceError("event.number must be a positive integer")
        metadata = client.pull(number)
        event_pr = _mapping(document.get("pull_request"), "event.pull_request")
        event_head = _mapping(event_pr.get("head"), "event.pull_request.head")
        target = _pull_target(metadata, base_override=None)
        if target.head_sha != _sha(
            event_head.get("sha"), "event.pull_request.head.sha"
        ):
            raise EvidenceError(
                "pull_request event is stale relative to current PR head"
            )
        return [target]

    merge_group = _mapping(document.get("merge_group"), "event.merge_group")
    group_head = _sha(merge_group.get("head_sha"), "event.merge_group.head_sha")
    group_base = _sha(merge_group.get("base_sha"), "event.merge_group.base_sha")
    head_ref = _text(merge_group.get("head_ref"), "event.merge_group.head_ref")
    numbers = {
        int(match.group("number")) for match in MERGE_QUEUE_PR.finditer(head_ref)
    }
    base_ref = _text(merge_group.get("base_ref"), "event.merge_group.base_ref")
    base_name = base_ref.removeprefix("refs/heads/")
    group_commits = {group_head, *client.commits_between(group_base, group_head)}
    for commit in sorted(group_commits):
        for associated in client.associated_pulls(commit):
            state = associated.get("state")
            base = _mapping(associated.get("base"), "associated pull base")
            number = associated.get("number")
            if (
                state == "open"
                and base.get("ref") == base_name
                and isinstance(number, int)
            ):
                numbers.add(number)
    if not numbers:
        raise EvidenceError(
            "merge_group did not identify any PR through head_ref or associated pulls"
        )
    targets: list[ReviewTarget] = []
    for number in sorted(numbers):
        metadata = client.pull(number)
        pull_base = _mapping(metadata.get("base"), f"pull request {number}.base")
        if pull_base.get("ref") != base_name:
            raise EvidenceError(
                f"pull request {number} does not target merge-group base {base_name}"
            )
        targets.append(_pull_target(metadata, base_override=group_base))
    if any(target.head_sha == group_head for target in targets):
        raise EvidenceError("merge-group synthetic head may not replace a PR head")
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Feature-Regression Reviewer evidence for PRs"
    )
    parser.add_argument("--event-path", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--policy-ref", required=True)
    parser.add_argument("--api-url", default="https://api.github.com")
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        client = GitHubClient(
            api_url=args.api_url,
            repository=args.repository,
            token=token,
        )
        with open(args.event_path, encoding="utf-8") as event_file:
            event = json.load(event_file)
        targets = review_targets(event, client)
        for target in targets:
            comment, evidence = validate_latest_comment(
                client.comments(target.number),
                repository=client.repository,
                current_base=target.base_sha,
                current_head=target.head_sha,
                trusted_policy_ref=args.policy_ref,
                changed_files=client.files(target.number),
                fetch_content=client.content,
                fetch_run=client.run,
                fetch_jobs=client.jobs,
                fetch_artifacts=client.artifacts,
                download_artifact=client.download_artifact,
                authority_resolver=client.permission,
                decision_fetcher=client.decision,
            )
            source = comment.get("html_url", f"PR #{target.number} comment")
            print(
                f"PR #{target.number}: feature-regression evidence passed for "
                f"{evidence['applicability']['decision']} at {target.head_sha} "
                f"({source})"
            )
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
