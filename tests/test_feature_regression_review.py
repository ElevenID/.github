from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import pathlib
import sys
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock


sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from scripts.feature_regression_review import (  # noqa: E402
    CANONICAL_JSON_METHOD,
    MARKER,
    EvidenceError,
    GitHubClient,
    ReviewTarget,
    canonical_json_digest,
    classify_changed_files,
    extract_evidence,
    review_targets,
    validate_evidence,
    validate_latest_comment,
)


REPOSITORY = "ElevenID/example"
HEAD = "a" * 40
BASE = "b" * 40
OLD = "c" * 40
TEST = f"test:{REPOSITORY}@{HEAD}:tests/test_api.py::test_approval_provider_failure"
BASE_TEST = (
    f"test:{REPOSITORY}@{BASE}:tests/test_api.py::test_approval_provider_failure"
)
ARTIFACT = "artifact:https://github.com/ElevenID/example/actions/runs/12345"
CATALOG_PATH = ".github/feature-regression/behavior-catalog.json"
WORKFLOW_PATH = ".github/workflows/behavior-observations.yml"
QUALITY_POLICY_SHA = "0ce5534d83c050166b706b93bed31d0e6c214ca8"
LEGACY_APPROVED_FEATURE_IMPLEMENTATION_SHA = "cdecf65ee23c9969f49f61e8d4a0946c95ab4bec"
APPROVED_FEATURE_IMPLEMENTATION_SHA = "41ce275e615b9ca9be11fde292e6d3b84c8b8ef5"
FUTURE_APPROVED_REPAIR_SHA = "e" * 40
HARNESS_PATH = ".github/feature-regression/observation_harness.py"
HARNESS_BYTES = b"""import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--repository")
parser.add_argument("--revision")
parser.add_argument("--phase", choices=("before", "after"), required=True)
args = parser.parse_args()
capture = json.load(sys.stdin)
if args.command == "test":
    assert capture["schema"] == "elevenid.behavior-subject-capture/v2"
    by_dimension = {
        item["dimension"]: item["value"] for item in capture["observations"]
    }
    assert set(by_dimension) == {
        "public_status",
        "public_message",
        "safe_server_diagnostic",
    }
    assert isinstance(by_dimension["public_status"], str)
    assert by_dimension["public_status"].startswith("HTTP ")
    assert isinstance(by_dimension["public_message"], str)
    assert by_dimension["public_message"].strip()
    diagnostic = by_dimension["safe_server_diagnostic"]
    assert isinstance(diagnostic, dict)
    assert diagnostic.get("category") and diagnostic.get("stage")
    raise SystemExit(0)
observations = [
    {
        **observed,
        "id": f"{observed['case_id']}.{observed['dimension']}.{args.phase}",
        "producer_test": (
            f"test:{args.repository}@{args.revision}:tests/test_api.py::"
            "test_approval_provider_failure"
        ),
    }
    for observed in capture["observations"]
]
document = {
    "schema": "elevenid.behavior-observations-runtime/v2",
    "repository": args.repository,
    "revision": args.revision,
    "phase": args.phase,
    "observations": observations,
}
sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
"""
HARNESS_SHA256 = f"sha256:{hashlib.sha256(HARNESS_BYTES).hexdigest()}"
SUBJECT_PATH = ".github/feature-regression/behavior_subject.py"
SUBJECT_BYTES = b"""import json
import sys

from src.api import probe_behavior

observed = probe_behavior()
document = {
    "schema": "elevenid.behavior-subject-output/v2",
    "observations": [
        {
            "id": "approval-provider-failure.public_status",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "public_status",
            "value": observed["public_status"],
        },
        {
            "id": "approval-provider-failure.public_message",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "public_message",
            "value": observed["public_message"],
        },
        {
            "id": "approval-provider-failure.safe_server_diagnostic",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "safe_server_diagnostic",
            "value": observed["safe_server_diagnostic"],
        },
    ],
}
sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
"""
SUBJECT_SHA256 = f"sha256:{hashlib.sha256(SUBJECT_BYTES).hexdigest()}"
SUBJECT_RUNTIME = "python"
SUBJECT_ARGS: list[str] = []
SUBJECT_ENV: dict[str, str] = {}
RUNTIME_IMAGE = (
    "python:3.12-alpine@sha256:"
    "236173eb74001afe2f60862de935b74fcbd00adfca247b2c27051a70a6a39a2d"
)
JOB_NAME = "behavior-observations / Behavior observation producer"
PRODUCE_STEP_NAME = "Produce trusted runtime observations atomically"
UPLOAD_STEP_NAME = "Upload runtime observations"
ARTIFACT_NAME_PREFIX = "feature-regression-observations"
ARTIFACT_NAME = f"{ARTIFACT_NAME_PREFIX}-12345-2"
BEFORE_ARTIFACT_NAME = f"{ARTIFACT_NAME_PREFIX}-12344-1"
OBSERVATION_MEMBER = "feature-regression-observations.json"
OPERATION_ID = "credential.approve"
CASE_ID = "approval-provider-failure"
PRODUCTION_FILES = [{"filename": "src/api.py", "status": "modified"}]
DOC_FILES = [{"filename": "docs/reviewer-guide.md", "status": "modified"}]


def observation_reference(phase: str, dimension: str) -> str:
    observation_id = f"{CASE_ID}.{dimension}.{phase}"
    run_id = 12344 if phase == "before" else 12345
    return f"artifact-observation:{REPOSITORY}@{run_id}:{observation_id}"


def snapshot(value: object, phase: str, dimension: str) -> dict[str, object]:
    return {"value": value, "evidence": [observation_reference(phase, dimension)]}


def comparison(value: object, dimension: str = "public_status") -> dict[str, object]:
    return {
        "disposition": "preserved",
        "before": snapshot(value, "before", dimension),
        "after": snapshot(value, "after", dimension),
    }


def applicable_evidence() -> dict[str, object]:
    return {
        "schema": "elevenid.feature-regression-review/v2",
        "repository": REPOSITORY,
        "reviewed_base": BASE,
        "reviewed_head": HEAD,
        "applicability": {
            "decision": "applicable",
            "rationale": "The change migrates an existing production operation.",
        },
        "reviewer": {
            "login": "reviewer",
            "role": "feature_regression_reviewer",
            "context": "fresh-read-only-session-42",
        },
        "implementation_context": "implementation-session-17",
        "sanitized_public_evidence": True,
        "behavior_catalog": f"catalog:{REPOSITORY}@{BASE}:{CATALOG_PATH}",
        "inventory_sources": [
            {
                "repository": REPOSITORY,
                "path": "src/api.py",
                "commit": OLD,
                "phase": "pre_change",
            }
        ],
        "findings": [],
        "commands": ["python -m pytest tests/test_api.py"],
        "tests": [TEST],
        "unexercised_surfaces": [],
        "residual_risks": [],
        "surface_coverage": {
            "entry_points": {"evidence": [TEST]},
            "request_validation": {"evidence": [TEST]},
            "success_behavior": {"evidence": [TEST]},
            "failure_semantics": {"evidence": [TEST]},
            "persistence_audit": {"evidence": [TEST]},
            "metrics_operator_diagnostics": {"evidence": [TEST]},
            "security_redaction": {"evidence": [TEST]},
            "failure_retry_concurrency": {"evidence": [TEST]},
            "configuration_deployment_consumers": {"evidence": [TEST]},
            "production_boundary_tests_demos": {"evidence": [ARTIFACT]},
        },
        "operations": [
            {
                "id": OPERATION_ID,
                "case_id": CASE_ID,
                "name": "approve credential",
                "public_status": comparison("HTTP 502", "public_status"),
                "public_message": comparison(
                    "Credential approval failed", "public_message"
                ),
                "safe_server_diagnostic": comparison(
                    {"stage": "approval", "category": "provider"},
                    "safe_server_diagnostic",
                ),
            }
        ],
        "behavior_dispositions": [
            {
                "behavior": "approval provider failure mapping",
                "disposition": "preserved",
                "evidence": [TEST],
            }
        ],
        "cross_boundary": {
            "applies": False,
            "method": None,
            "common_sha256": None,
            "sources": [],
        },
    }


OBSERVATION_VALUES = {
    "public_status": "HTTP 502",
    "public_message": "Credential approval failed",
    "safe_server_diagnostic": {"stage": "approval", "category": "provider"},
}


def subject_output_bytes() -> bytes:
    document = {
        "schema": "elevenid.behavior-subject-output/v2",
        "observations": [
            {
                "id": f"{CASE_ID}.{dimension}",
                "operation_id": OPERATION_ID,
                "case_id": CASE_ID,
                "dimension": dimension,
                "value": value,
            }
            for dimension, value in OBSERVATION_VALUES.items()
        ],
    }
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def producer_workflow_bytes() -> bytes:
    return f"""name: feature-regression-observation-producer

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
    uses: ElevenID/.github/.github/workflows/feature-regression-observation-producer.yml@{FUTURE_APPROVED_REPAIR_SHA}
    with:
      policy-ref: {FUTURE_APPROVED_REPAIR_SHA}
      target-ref: ${{{{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}}}
      phase: ${{{{ github.event_name == 'pull_request' && 'after' || 'before' }}}}
      workflow-path: {WORKFLOW_PATH}
      harness-path: {HARNESS_PATH}
      harness-sha256: {HARNESS_SHA256}
      subject-path: {SUBJECT_PATH}
      subject-sha256: {SUBJECT_SHA256}
      subject-runtime: {SUBJECT_RUNTIME}
      subject-args-json: '[]'
      subject-env-json: '{{}}'
      runtime-image: {RUNTIME_IMAGE}
      job-name: {JOB_NAME}
      artifact-name-prefix: {ARTIFACT_NAME_PREFIX}
      observation-path: {OBSERVATION_MEMBER}
""".encode()


WORKFLOW_SHA256 = f"sha256:{hashlib.sha256(producer_workflow_bytes()).hexdigest()}"


def catalog_bytes() -> bytes:
    return json.dumps(
        {
            "schema": "elevenid.behavior-catalog/v3",
            "repository": REPOSITORY,
            "producer": {
                "workflow_path": WORKFLOW_PATH,
                "workflow_sha256": WORKFLOW_SHA256,
                "central_workflow_sha": FUTURE_APPROVED_REPAIR_SHA,
                "harness_path": HARNESS_PATH,
                "harness_sha256": HARNESS_SHA256,
                "subject_path": SUBJECT_PATH,
                "subject_sha256": SUBJECT_SHA256,
                "subject_runtime": SUBJECT_RUNTIME,
                "subject_args": SUBJECT_ARGS,
                "subject_env": SUBJECT_ENV,
                "runtime_image": RUNTIME_IMAGE,
                "job_name": JOB_NAME,
                "produce_step_name": PRODUCE_STEP_NAME,
                "upload_step_name": UPLOAD_STEP_NAME,
                "artifact_name_prefix": ARTIFACT_NAME_PREFIX,
                "observation_path": OBSERVATION_MEMBER,
            },
            "operations": [
                {
                    "id": OPERATION_ID,
                    "name": "approve credential",
                    "cases": [
                        {
                            "id": CASE_ID,
                            "components": ["src/api.py"],
                            "invariants": [
                                "public_status",
                                "public_message",
                                "safe_server_diagnostic",
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def observation_bytes(phase: str, overrides: dict[str, object] | None = None) -> bytes:
    values = {**OBSERVATION_VALUES, **(overrides or {})}
    commit = BASE if phase == "before" else HEAD
    document: dict[str, object] = {
        "schema": "elevenid.behavior-observations/v3",
        "repository": REPOSITORY,
        "revision": commit,
        "phase": phase,
        "observations": [
            {
                "id": f"{CASE_ID}.{dimension}.{phase}",
                "operation_id": OPERATION_ID,
                "case_id": CASE_ID,
                "dimension": dimension,
                "value": value,
                "producer_test": BASE_TEST if phase == "before" else TEST,
            }
            for dimension, value in values.items()
        ],
    }
    document["runtime_receipt"] = {
        "runtime_image": RUNTIME_IMAGE,
        "subject_path": SUBJECT_PATH,
        "subject_sha256": SUBJECT_SHA256,
        "runtime": SUBJECT_RUNTIME,
        "arguments": SUBJECT_ARGS,
        "environment": {
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        },
        "exit_code": 0,
        "stdout_sha256": (
            f"sha256:{hashlib.sha256(subject_output_bytes()).hexdigest()}"
        ),
        "stderr_sha256": f"sha256:{hashlib.sha256(b'').hexdigest()}",
    }
    run_id = 12344 if phase == "before" else 12345
    run_attempt = 1 if phase == "before" else 2
    artifact_name = BEFORE_ARTIFACT_NAME if phase == "before" else ARTIFACT_NAME
    event_name = "push" if phase == "before" else "pull_request"
    head_branch = "main" if phase == "before" else "feature/probe"
    document["producer"] = {
        "workflow_path": WORKFLOW_PATH,
        "workflow_sha256": WORKFLOW_SHA256,
        "central_workflow_sha": FUTURE_APPROVED_REPAIR_SHA,
        "harness_path": HARNESS_PATH,
        "harness_sha256": HARNESS_SHA256,
        "subject_path": SUBJECT_PATH,
        "subject_sha256": SUBJECT_SHA256,
        "subject_runtime": SUBJECT_RUNTIME,
        "subject_args": SUBJECT_ARGS,
        "subject_env": SUBJECT_ENV,
        "runtime_image": RUNTIME_IMAGE,
        "job_name": JOB_NAME,
        "artifact_name": artifact_name,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "head_sha": commit,
        "phase": phase,
        "event_name": event_name,
        "head_branch": head_branch,
    }
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def artifact_zip(
    phase: str = "after", overrides: dict[str, object] | None = None
) -> bytes:
    output = io.BytesIO()
    info = zipfile.ZipInfo(OBSERVATION_MEMBER, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr(info, observation_bytes(phase, overrides))
    return output.getvalue()


def artifact_document_zip(document: dict[str, object]) -> bytes:
    output = io.BytesIO()
    info = zipfile.ZipInfo(OBSERVATION_MEMBER, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    payload = json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr(info, payload)
    return output.getvalue()


def artifact_metadata(archive: bytes, phase: str = "after") -> dict[str, object]:
    run_id = 12344 if phase == "before" else 12345
    commit = BASE if phase == "before" else HEAD
    return {
        "id": 455 if phase == "before" else 456,
        "name": BEFORE_ARTIFACT_NAME if phase == "before" else ARTIFACT_NAME,
        "expired": False,
        "digest": f"sha256:{hashlib.sha256(archive).hexdigest()}",
        "workflow_run": {
            "id": run_id,
            "head_sha": commit,
            "head_branch": "main" if phase == "before" else "feature/probe",
            "repository_id": 99,
            "head_repository_id": 99,
        },
    }


def default_fetch(repository: str, path: str, commit: str) -> bytes:
    if (repository, path, commit) == (REPOSITORY, "src/api.py", OLD):
        return b"production inventory"
    if (
        repository == REPOSITORY
        and path == "tests/test_api.py"
        and commit
        in {
            BASE,
            HEAD,
        }
    ):
        return b"def test_approval_provider_failure(): pass"
    if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
        return catalog_bytes()
    if repository == REPOSITORY and path == WORKFLOW_PATH and commit in {BASE, HEAD}:
        return producer_workflow_bytes()
    if repository == REPOSITORY and path == HARNESS_PATH and commit in {BASE, HEAD}:
        return HARNESS_BYTES
    if repository == REPOSITORY and path == SUBJECT_PATH and commit in {BASE, HEAD}:
        return SUBJECT_BYTES
    raise AssertionError(f"unexpected fetch {repository}/{path}@{commit}")


def artifact_with_after(
    overrides: dict[str, object],
    *,
    before_overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    archive = artifact_zip(overrides=overrides)
    before_archive = artifact_zip("before", before_overrides)

    def fetch_artifacts(repository: str, run_id: int) -> list[dict[str, object]]:
        if repository != REPOSITORY or run_id not in {12344, 12345}:
            raise AssertionError(f"unexpected artifacts {repository}/{run_id}")
        if run_id == 12344:
            return [artifact_metadata(before_archive, "before")]
        return [artifact_metadata(archive, "after")]

    def download(repository: str, artifact_id: int) -> bytes:
        if repository != REPOSITORY or artifact_id not in {455, 456}:
            raise AssertionError(
                f"unexpected artifact download {repository}/{artifact_id}"
            )
        return before_archive if artifact_id == 455 else archive

    return {"fetch_artifacts": fetch_artifacts, "download_artifact": download}


def artifact_with_archive(
    after_archive: bytes,
    *,
    after_metadata: dict[str, object] | None = None,
    before_archive: bytes | None = None,
) -> dict[str, object]:
    before_archive = before_archive or artifact_zip("before")

    def fetch_artifacts(repository: str, run_id: int) -> list[dict[str, object]]:
        if repository != REPOSITORY or run_id not in {12344, 12345}:
            raise AssertionError(f"unexpected artifacts {repository}/{run_id}")
        if run_id == 12344:
            return [artifact_metadata(before_archive, "before")]
        return [after_metadata or artifact_metadata(after_archive)]

    def download(repository: str, artifact_id: int) -> bytes:
        if repository != REPOSITORY or artifact_id not in {455, 456}:
            raise AssertionError(
                f"unexpected artifact download {repository}/{artifact_id}"
            )
        return before_archive if artifact_id == 455 else after_archive

    return {"fetch_artifacts": fetch_artifacts, "download_artifact": download}


def jobs_with_after(after_jobs: list[dict[str, object]]):
    def fetch_jobs(
        repository: str, run_id: int, run_attempt: int
    ) -> list[dict[str, object]]:
        if run_id == 12344:
            return successful_jobs(repository, run_id, run_attempt)
        return after_jobs

    return fetch_jobs


def decision_bytes(
    *,
    impact: str,
    replacement: str,
    breaking_loss: bool = False,
    approved_by: str = "reviewer",
    before_value: object = "Credential approval failed",
    after_value: object = "Replacement approval message",
) -> bytes:
    before_digest = f"sha256:{hashlib.sha256(json.dumps(before_value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}"
    after_digest = f"sha256:{hashlib.sha256(json.dumps(after_value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}"
    return json.dumps(
        {
            "schema": "elevenid.intentional-change-decisions/v1",
            "decisions": [
                {
                    "id": "approval-message",
                    "repository": REPOSITORY,
                    "scope": {
                        "kind": "operation_dimension",
                        "operation": "approve credential",
                        "dimension": "public_message",
                    },
                    "approved_by": approved_by,
                    "before_value": before_value,
                    "after_value": after_value,
                    "before_sha256": before_digest,
                    "after_sha256": after_digest,
                    "compatibility_impact": impact,
                    "replacement_behavior": replacement,
                    "breaking_loss": breaking_loss,
                }
            ],
        }
    ).encode()


def successful_run(repository: str, run_id: int) -> dict[str, object]:
    if repository != REPOSITORY or run_id not in {12344, 12345}:
        raise AssertionError(f"unexpected run {repository}/{run_id}")
    return {
        "status": "completed",
        "conclusion": "success",
        "head_sha": BASE if run_id == 12344 else HEAD,
        "event": "push" if run_id == 12344 else "pull_request",
        "head_branch": "main" if run_id == 12344 else "feature/probe",
        "run_attempt": 1 if run_id == 12344 else 2,
        "path": f"{WORKFLOW_PATH}@refs/heads/main",
        "repository": {"id": 99, "full_name": REPOSITORY},
        "head_repository": {"id": 99, "full_name": REPOSITORY},
    }


def successful_jobs(
    repository: str, run_id: int, run_attempt: int
) -> list[dict[str, object]]:
    expected_attempt = 1 if run_id == 12344 else 2
    if (
        repository != REPOSITORY
        or run_id not in {12344, 12345}
        or run_attempt != expected_attempt
    ):
        raise AssertionError(f"unexpected jobs {repository}/{run_id}/{run_attempt}")
    return [
        {
            "name": JOB_NAME,
            "status": "completed",
            "conclusion": "success",
            "run_id": run_id,
            "head_sha": BASE if run_id == 12344 else HEAD,
            "steps": [
                {
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                }
                for name in (PRODUCE_STEP_NAME, UPLOAD_STEP_NAME)
            ],
        }
    ]


def successful_artifacts(repository: str, run_id: int) -> list[dict[str, object]]:
    if repository != REPOSITORY or run_id not in {12344, 12345}:
        raise AssertionError(f"unexpected artifacts {repository}/{run_id}")
    phase = "before" if run_id == 12344 else "after"
    archive = artifact_zip(phase)
    return [artifact_metadata(archive, phase)]


def successful_download(repository: str, artifact_id: int) -> bytes:
    if repository != REPOSITORY or artifact_id not in {455, 456}:
        raise AssertionError(f"unexpected artifact download {repository}/{artifact_id}")
    return artifact_zip("before" if artifact_id == 455 else "after")


def comment(evidence: dict[str, object], author: str = "reviewer") -> dict[str, object]:
    return {
        "body": f"{MARKER}\n```json\n{json.dumps(evidence)}\n```",
        "html_url": "https://github.com/ElevenID/example/pull/1#issuecomment-1",
        "author_association": "MEMBER",
        "user": {"login": author},
    }


class FakeClient:
    def __init__(
        self,
        pulls: dict[int, dict[str, object]],
        associated: list[dict[str, object]] | None = None,
    ) -> None:
        self.pulls = pulls
        self.associated = associated or []

    def pull(self, number: int) -> dict[str, object]:
        return self.pulls[number]

    def associated_pulls(self, commit: str) -> list[dict[str, object]]:
        self.associated_commit = commit
        return self.associated

    def commits_between(self, base: str, head: str) -> list[str]:
        self.comparison = (base, head)
        return ["d" * 40]


class FeatureRegressionReviewTests(unittest.TestCase):
    def validate(
        self,
        evidence: dict[str, object],
        *,
        files: list[dict[str, str]] | None = None,
        association: str = "MEMBER",
        fetch=default_fetch,
        fetch_run=successful_run,
        fetch_jobs=successful_jobs,
        fetch_artifacts=successful_artifacts,
        download_artifact=successful_download,
        authority=lambda _login: {"permission": "maintain", "role_name": "maintain"},
        fetch_decision=lambda _url: b"{}",
    ) -> dict[str, object]:
        return dict(
            validate_evidence(
                evidence,
                repository=REPOSITORY,
                current_base=BASE,
                current_head=HEAD,
                trusted_policy_ref=FUTURE_APPROVED_REPAIR_SHA,
                comment_author="reviewer",
                comment_author_association=association,
                changed_files=files or PRODUCTION_FILES,
                fetch_content=fetch,
                fetch_run=fetch_run,
                fetch_jobs=fetch_jobs,
                fetch_artifacts=fetch_artifacts,
                download_artifact=download_artifact,
                authority_resolver=authority,
                decision_fetcher=fetch_decision,
            )
        )

    def assert_invalid(
        self,
        evidence: dict[str, object],
        expected: str,
        **kwargs,
    ) -> None:
        with self.assertRaisesRegex(EvidenceError, expected):
            self.validate(evidence, **kwargs)

    def test_accepts_complete_applicable_evidence(self) -> None:
        result = self.validate(applicable_evidence())
        self.assertEqual("applicable", result["applicability"]["decision"])

    def test_rejects_unknown_schema_fields(self) -> None:
        evidence = applicable_evidence()
        evidence["unverified_claim"] = True
        self.assert_invalid(evidence, "fields do not match the schema")

    def test_documented_example_matches_validator(self) -> None:
        repository_root = pathlib.Path(__file__).parents[1]
        path = (
            repository_root
            / "maintenance"
            / "feature-regression-review-evidence.example.json"
        )
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.validate(evidence)

        attributes = (repository_root / ".gitattributes").read_text(encoding="utf-8")
        for pinned_pattern in (
            "/.github/workflows/feature-regression-*.yml",
            "/maintenance/feature-regression-*",
            "/scripts/feature_regression_*.py",
            "/tests/test_feature_regression_*.py",
        ):
            self.assertIn(f"{pinned_pattern} text eol=lf", attributes.splitlines())

        reviewer_documentation = (
            repository_root / "maintenance" / "feature-regression-reviewer.md"
        ).read_text(encoding="utf-8")
        self.assertIn(QUALITY_POLICY_SHA, reviewer_documentation)
        self.assertIn("QUALITY_POLICY_SHA", reviewer_documentation)
        self.assertIn(
            LEGACY_APPROVED_FEATURE_IMPLEMENTATION_SHA, reviewer_documentation
        )
        self.assertIn("APPROVED_FEATURE_IMPLEMENTATION_SHA", reviewer_documentation)
        self.assertIn(FUTURE_APPROVED_REPAIR_SHA, reviewer_documentation)
        self.assertIn("does not accept the v2/v3 phase input", reviewer_documentation)
        self.assertNotIn("`POLICY_SHA`", reviewer_documentation)
        self.assertIn("retained for 90 days", reviewer_documentation)
        self.assertIn("head branch", reviewer_documentation)
        self.assertIn("`post_change` inventory source", reviewer_documentation)
        self.assertIn(
            "Do not add a Rust repository to `enabled_repositories`",
            reviewer_documentation,
        )

        maintenance = path.parent
        activation = json.loads(
            (maintenance / "feature-regression-approved-revisions.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            APPROVED_FEATURE_IMPLEMENTATION_SHA,
            activation["approved_revision"],
        )
        self.assertEqual([], activation["enabled_repositories"])
        self.assertNotEqual(
            activation["approved_revision"],
            LEGACY_APPROVED_FEATURE_IMPLEMENTATION_SHA,
        )
        self.assertNotEqual(activation["approved_revision"], FUTURE_APPROVED_REPAIR_SHA)
        self.assertEqual(
            json.loads(catalog_bytes()),
            json.loads(
                (
                    maintenance / "feature-regression-behavior-catalog.example.json"
                ).read_text(encoding="utf-8")
            ),
        )
        self.assertEqual(
            HARNESS_BYTES,
            (maintenance / "feature-regression-observation-harness.example.py")
            .read_text(encoding="utf-8")
            .encode("utf-8"),
        )
        self.assertEqual(
            SUBJECT_BYTES,
            (maintenance / "feature-regression-behavior-subject.example.py")
            .read_text(encoding="utf-8")
            .encode("utf-8"),
        )
        self.assertEqual(
            producer_workflow_bytes(),
            (maintenance / "feature-regression-observation-caller.example.yml")
            .read_text(encoding="utf-8")
            .encode("utf-8"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "src"
            source.mkdir()
            (source / "__init__.py").write_text("", encoding="utf-8")
            (source / "api.py").write_text(
                f"def probe_behavior():\n    return {OBSERVATION_VALUES!r}\n",
                encoding="utf-8",
            )
            subject = root / "behavior_subject.py"
            subject.write_bytes(SUBJECT_BYTES)
            subject_result = subprocess.run(
                [sys.executable, str(subject)],
                cwd=root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
            )
        self.assertEqual(subject_output_bytes(), subject_result.stdout)
        self.assertEqual(b"", subject_result.stderr)
        artifact_example = (
            (maintenance / "feature-regression-artifact-observations.example.json")
            .read_text(encoding="utf-8")
            .encode("utf-8")
        )
        self.assertEqual(observation_bytes("after"), artifact_example.rstrip(b"\n"))
        before_artifact_example = (
            (
                maintenance
                / "feature-regression-before-artifact-observations.example.json"
            )
            .read_text(encoding="utf-8")
            .encode("utf-8")
        )
        self.assertEqual(
            observation_bytes("before"), before_artifact_example.rstrip(b"\n")
        )
        self.assertFalse(
            (maintenance / "feature-regression-observations.example.json").exists()
        )
        producer = (
            repository_root
            / ".github"
            / "workflows"
            / "feature-regression-observation-producer.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("retention-days: 90", producer)
        artifact_document = json.loads(artifact_example)
        self.assertEqual(
            f"sha256:{hashlib.sha256(subject_result.stdout).hexdigest()}",
            artifact_document["runtime_receipt"]["stdout_sha256"],
        )
        self.assertEqual(
            f"sha256:{hashlib.sha256(subject_result.stderr).hexdigest()}",
            artifact_document["runtime_receipt"]["stderr_sha256"],
        )
        self.assertEqual(
            json.loads(
                decision_bytes(
                    impact="Clients see intentionally revised wording.",
                    replacement="Approval remains operation-specific.",
                )
            ),
            json.loads(
                (maintenance / "feature-regression-decisions.example.json").read_text(
                    encoding="utf-8"
                )
            ),
        )

    def test_binds_repository_base_and_head(self) -> None:
        for field, value, expected in (
            ("repository", "ElevenID/other", "current repository"),
            ("reviewed_base", "d" * 40, "actual base"),
            ("reviewed_head", "e" * 40, "current PR head"),
        ):
            with self.subTest(field=field):
                evidence = applicable_evidence()
                evidence[field] = value
                self.assert_invalid(evidence, expected)

    def test_requires_authorized_commenter_for_every_decision(self) -> None:
        self.assert_invalid(
            applicable_evidence(),
            "OWNER, MEMBER, or COLLABORATOR",
            association="NONE",
        )

    def test_binds_reviewer_identity_and_distinct_context(self) -> None:
        evidence = applicable_evidence()
        evidence["reviewer"]["login"] = "someone-else"
        self.assert_invalid(evidence, "must match the evidence comment author")
        evidence = applicable_evidence()
        evidence["implementation_context"] = "FRESH-READ-ONLY-SESSION-42"
        self.assert_invalid(evidence, "must be distinct")

    def test_accepts_not_applicable_only_for_obvious_docs_or_tests(self) -> None:
        evidence = applicable_evidence()
        evidence["applicability"] = {
            "decision": "not_applicable",
            "rationale": "Only the reviewer guide changed.",
        }
        evidence["operations"] = []
        evidence["behavior_dispositions"] = []
        evidence["behavior_catalog"] = None
        self.validate(evidence, files=DOC_FILES)

    def test_governance_catalog_harness_and_producer_changes_require_review(
        self,
    ) -> None:
        for path in (
            CATALOG_PATH,
            HARNESS_PATH,
            SUBJECT_PATH,
            WORKFLOW_PATH,
            ".github/feature-regression/base-observations.json",
            ".github/feature-regression/tests/test_harness.py",
            ".github/feature-regression/test_fixture.json",
        ):
            with self.subTest(path=path):
                evidence = applicable_evidence()
                evidence["applicability"] = {
                    "decision": "not_applicable",
                    "rationale": "Claimed test-only maintenance.",
                }
                evidence["operations"] = []
                evidence["behavior_dispositions"] = []
                evidence["behavior_catalog"] = None
                self.assert_invalid(
                    evidence,
                    "not_applicable is forbidden",
                    files=[{"filename": path, "status": "modified"}],
                )

    def test_migration_cannot_claim_not_applicable(self) -> None:
        evidence = applicable_evidence()
        evidence["applicability"] = {
            "decision": "not_applicable",
            "rationale": "Claimed docs-only.",
        }
        evidence["operations"] = []
        evidence["behavior_dispositions"] = []
        evidence["behavior_catalog"] = None
        self.assert_invalid(
            evidence,
            "not_applicable is forbidden",
            files=[{"filename": "migrations/retire_python.py", "status": "added"}],
        )

    def test_deletion_or_rename_cannot_claim_not_applicable(self) -> None:
        evidence = applicable_evidence()
        evidence["applicability"] = {
            "decision": "not_applicable",
            "rationale": "Claimed tests-only.",
        }
        evidence["operations"] = []
        evidence["behavior_dispositions"] = []
        evidence["behavior_catalog"] = None
        for file in (
            {"filename": "tests/test_old.py", "status": "removed"},
            {
                "filename": "docs/new.md",
                "previous_filename": "docs/old.md",
                "status": "renamed",
            },
        ):
            with self.subTest(file=file):
                self.assert_invalid(
                    evidence, "not_applicable is forbidden", files=[file]
                )

    def test_uncertain_change_cannot_claim_not_applicable(self) -> None:
        evidence = applicable_evidence()
        evidence["applicability"] = {
            "decision": "not_applicable",
            "rationale": "Unknown file.",
        }
        evidence["operations"] = []
        evidence["behavior_dispositions"] = []
        evidence["behavior_catalog"] = None
        self.assert_invalid(
            evidence,
            "uncertain",
            files=[{"filename": ".gitignore", "status": "modified"}],
        )

    def test_root_executable_is_classified_as_production(self) -> None:
        classification, reason = classify_changed_files(
            [{"filename": "release.py", "status": "modified"}]
        )
        self.assertEqual("production", classification)
        self.assertIn("executable source", reason)

    def test_classifier_recognizes_tests_and_rejects_contract_docs(self) -> None:
        self.assertEqual(
            "docs_tests_only",
            classify_changed_files(
                [{"filename": "tests/test_api.py", "status": "modified"}]
            )[0],
        )
        self.assertNotEqual(
            "docs_tests_only",
            classify_changed_files(
                [{"filename": "docs/api-contract.md", "status": "modified"}]
            )[0],
        )

    def test_preserved_dimension_requires_equal_before_and_after(self) -> None:
        evidence = applicable_evidence()
        evidence["operations"][0]["public_message"]["after"]["value"] = (
            "Credential issuance failed"
        )
        self.assert_invalid(evidence, "must be intentionally_changed")

    def test_json_boolean_and_number_are_not_equal(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["public_status"]
        dimension["before"]["value"] = 1
        dimension["after"]["value"] = True
        self.assert_invalid(evidence, "must be intentionally_changed")

    def test_moved_dimension_requires_owner_and_test_mapping(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["safe_server_diagnostic"]
        dimension["disposition"] = "moved"
        self.assert_invalid(evidence, "moved_owner")
        dimension["moved_owner"] = REPOSITORY
        dimension["test_mapping"] = {"before": BASE_TEST, "after": TEST}
        self.validate(evidence)
        dimension["test_mapping"]["before"] = (
            f"test:{REPOSITORY}@{OLD}:tests/test_api.py::test_approval_provider_failure"
        )
        self.assert_invalid(evidence, "outside the permitted evidence phase")

    def test_moved_test_mapping_allows_only_phase_authorized_exact_sources(
        self,
    ) -> None:
        external = "ElevenID/consumer"
        pre_commit = "1" * 40
        post_commit = "2" * 40
        pre_path = "tests/test_legacy.py"
        post_path = "tests/test_replacement.py"
        contract_path = "contracts/approval.json"
        contract = b'{"operation":"credential.approve","status":502}'
        digest = canonical_json_digest(contract)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": REPOSITORY,
                "path": contract_path,
                "commit": HEAD,
                "phase": "post_change",
            },
            {
                "repository": external,
                "path": contract_path,
                "commit": post_commit,
                "phase": "post_change",
            },
            {
                "repository": external,
                "path": pre_path,
                "commit": pre_commit,
                "phase": "pre_change",
            },
            {
                "repository": external,
                "path": post_path,
                "commit": post_commit,
                "phase": "post_change",
            },
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": REPOSITORY,
                    "path": contract_path,
                    "commit": HEAD,
                    "sha256": digest,
                },
                {
                    "repository": external,
                    "path": contract_path,
                    "commit": post_commit,
                    "sha256": digest,
                },
            ],
        }
        dimension = evidence["operations"][0]["safe_server_diagnostic"]
        dimension["disposition"] = "moved"
        dimension["moved_owner"] = external
        before_ref = f"test:{external}@{pre_commit}:{pre_path}::test_legacy_failure"
        after_ref = (
            f"test:{external}@{post_commit}:{post_path}::test_replacement_failure"
        )
        dimension["test_mapping"] = {"before": before_ref, "after": after_ref}
        disposition = evidence["behavior_dispositions"][0]
        disposition["disposition"] = "moved"
        disposition["new_owner"] = external
        disposition["test_mapping"] = {
            "before": before_ref,
            "after": after_ref,
        }

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) in {
                (REPOSITORY, contract_path, HEAD),
                (external, contract_path, post_commit),
            }:
                return contract
            if (repository, path, commit) == (external, pre_path, pre_commit):
                return b"def test_legacy_failure(): pass"
            if (repository, path, commit) == (external, post_path, post_commit):
                return b"def test_replacement_failure(): pass"
            return default_fetch(repository, path, commit)

        self.validate(evidence, fetch=fetch)
        substitutions = (
            ("before", after_ref),
            ("after", before_ref),
            (
                "before",
                f"test:ElevenID/other@{pre_commit}:{pre_path}::test_legacy_failure",
            ),
            (
                "before",
                f"test:{external}@{'3' * 40}:{pre_path}::test_legacy_failure",
            ),
            (
                "before",
                f"test:{external}@{pre_commit}:tests/test_other.py::test_legacy_failure",
            ),
        )
        for phase, reference in substitutions:
            with self.subTest(phase=phase, reference=reference):
                candidate = copy.deepcopy(evidence)
                candidate["operations"][0]["safe_server_diagnostic"]["test_mapping"][
                    phase
                ] = reference
                self.assert_invalid(
                    candidate,
                    "outside the permitted evidence phase",
                    fetch=fetch,
                )

        candidate = copy.deepcopy(evidence)
        candidate["tests"] = [after_ref]
        self.assert_invalid(
            candidate, "outside the permitted evidence phase", fetch=fetch
        )

        candidate = copy.deepcopy(evidence)
        candidate["behavior_dispositions"][0]["test_mapping"]["before"] = after_ref
        self.assert_invalid(
            candidate, "outside the permitted evidence phase", fetch=fetch
        )

        before_document = json.loads(observation_bytes("before"))
        before_document["observations"][0]["producer_test"] = before_ref
        self.assert_invalid(
            evidence,
            "outside the permitted evidence phase",
            fetch=fetch,
            **artifact_with_archive(
                artifact_zip(),
                before_archive=artifact_document_zip(before_document),
            ),
        )

    def test_changed_dimension_requires_authorized_intentional_decision(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["public_message"]
        dimension["disposition"] = "intentionally_changed"
        dimension["after"]["value"] = "Replacement approval message"
        dimension["decision"] = {
            "approved_by": "reviewer",
            "authority_role": "repository_maintainer",
            "decision_ref": (
                f"decision:{REPOSITORY}@{BASE}:decisions/feature-loss.json#"
                "approval-message"
            ),
            "compatibility_impact": "Clients see intentionally revised wording.",
            "replacement_behavior": "Approval remains operation-specific.",
            "breaking_loss": False,
            "before_value": "Credential approval failed",
            "after_value": "Replacement approval message",
        }
        self.validate(
            evidence,
            **artifact_with_after({"public_message": "Replacement approval message"}),
            fetch_decision=lambda _url: decision_bytes(
                impact="Clients see intentionally revised wording.",
                replacement="Approval remains operation-specific.",
            ),
        )
        dimension["decision"]["approved_by"] = "someone-else"
        self.assert_invalid(evidence, "must match the evidence commenter")

    def test_rejects_loose_test_and_artifact_references(self) -> None:
        evidence = applicable_evidence()
        evidence["tests"] = ["test:test_api"]
        self.assert_invalid(evidence, "test:<owner/repo>@<40sha>:<path>::<test token>")
        evidence = applicable_evidence()
        evidence["surface_coverage"]["entry_points"]["evidence"] = [
            "artifact:https://example.test/run/1"
        ]
        self.assert_invalid(evidence, "ElevenID/<repo>/actions/runs")

    def test_test_reference_must_resolve_at_an_allowed_exact_commit(self) -> None:
        evidence = applicable_evidence()
        disallowed = "d" * 40
        evidence["tests"] = [
            f"test:{REPOSITORY}@{disallowed}:tests/test_api.py::test_present"
        ]
        self.assert_invalid(evidence, "outside the permitted evidence phase")

        evidence = applicable_evidence()

        def missing(repository: str, path: str, commit: str) -> bytes:
            if path != "tests/test_api.py":
                return default_fetch(repository, path, commit)
            raise EvidenceError("exact test file missing")

        self.assert_invalid(evidence, "exact test file missing", fetch=missing)

    def test_test_reference_must_use_a_recognized_test_path(self) -> None:
        evidence = applicable_evidence()
        evidence["tests"] = [
            f"test:{REPOSITORY}@{HEAD}:src/api.py::test_approval_provider_failure"
        ]
        self.assert_invalid(evidence, "recognized test path")

    def test_base_catalog_maps_every_changed_production_path_and_invariant(
        self,
    ) -> None:
        self.assert_invalid(
            applicable_evidence(),
            "unmapped in the base behavior catalog",
            files=[{"filename": "src/unmapped.py", "status": "modified"}],
        )
        catalog = json.loads(catalog_bytes())
        catalog["operations"][0]["cases"][0]["invariants"].remove(
            "safe_server_diagnostic"
        )

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
                return json.dumps(catalog).encode()
            return default_fetch(repository, path, commit)

        self.assert_invalid(
            applicable_evidence(), "exact operation triple", fetch=fetch
        )

    def test_producer_workflow_and_harness_are_immutable_base_anchors(self) -> None:
        for changed_path, expected in (
            (WORKFLOW_PATH, "workflow must be byte-identical"),
            (HARNESS_PATH, "harness must be byte-identical"),
            (SUBJECT_PATH, "subject must be byte-identical"),
        ):
            with self.subTest(path=changed_path):

                def fetch(repository: str, path: str, commit: str) -> bytes:
                    if (repository, path, commit) == (
                        REPOSITORY,
                        changed_path,
                        HEAD,
                    ):
                        return b"pull-request replacement\n"
                    return default_fetch(repository, path, commit)

                self.assert_invalid(applicable_evidence(), expected, fetch=fetch)

        malicious_workflow = producer_workflow_bytes() + b"# extra upload job\n"
        catalog = json.loads(catalog_bytes())
        catalog["producer"]["workflow_sha256"] = (
            f"sha256:{hashlib.sha256(malicious_workflow).hexdigest()}"
        )

        def malicious_fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
                return json.dumps(catalog).encode()
            if (
                repository == REPOSITORY
                and path == WORKFLOW_PATH
                and commit
                in {
                    BASE,
                    HEAD,
                }
            ):
                return malicious_workflow
            return default_fetch(repository, path, commit)

        self.assert_invalid(
            applicable_evidence(),
            "not the exact pinned central reusable caller",
            fetch=malicious_fetch,
        )

    def test_catalog_cannot_select_a_different_central_producer_revision(self) -> None:
        catalog = json.loads(catalog_bytes())
        catalog["producer"]["central_workflow_sha"] = "d" * 40

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
                return json.dumps(catalog).encode()
            return default_fetch(repository, path, commit)

        self.assert_invalid(
            applicable_evidence(),
            "central workflow SHA must match the trusted policy ref",
            fetch=fetch,
        )

    def test_v3_catalog_rejects_the_legacy_approved_implementation(self) -> None:
        with self.assertRaisesRegex(
            EvidenceError, "central workflow SHA must match the trusted policy ref"
        ):
            validate_evidence(
                applicable_evidence(),
                repository=REPOSITORY,
                current_base=BASE,
                current_head=HEAD,
                trusted_policy_ref=LEGACY_APPROVED_FEATURE_IMPLEMENTATION_SHA,
                comment_author="reviewer",
                comment_author_association="MEMBER",
                changed_files=PRODUCTION_FILES,
                fetch_content=default_fetch,
                fetch_run=successful_run,
                fetch_jobs=successful_jobs,
                fetch_artifacts=successful_artifacts,
                download_artifact=successful_download,
                authority_resolver=lambda _login: {
                    "permission": "maintain",
                    "role_name": "maintain",
                },
                decision_fetcher=lambda _url: b"{}",
            )

    def test_catalog_must_name_the_honest_atomic_producer_step(self) -> None:
        catalog = json.loads(catalog_bytes())
        catalog["producer"]["produce_step_name"] = "Set up Python"

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
                return json.dumps(catalog).encode()
            return default_fetch(repository, path, commit)

        self.assert_invalid(
            applicable_evidence(),
            "must identify the atomic producer and upload steps",
            fetch=fetch,
        )

    def test_catalog_runtime_image_must_be_digest_pinned(self) -> None:
        catalog = json.loads(catalog_bytes())
        catalog["producer"]["runtime_image"] = "python:3.12-alpine"

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (REPOSITORY, CATALOG_PATH, BASE):
                return json.dumps(catalog).encode()
            return default_fetch(repository, path, commit)

        self.assert_invalid(
            applicable_evidence(),
            "runtime_image must be pinned by sha256 digest",
            fetch=fetch,
        )

    def test_caller_triggers_and_phase_selection_are_immutable(self) -> None:
        mutations = (
            (
                "  push:\n    branches: [main]\n",
                "",
            ),
            (
                '  schedule:\n    - cron: "17 6 * * 1"\n',
                "",
            ),
            ("  workflow_dispatch:\n", ""),
            (
                "phase: ${{ github.event_name == 'pull_request' && 'after' || 'before' }}",
                "phase: after",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(original=original):
                workflow = (
                    producer_workflow_bytes()
                    .decode()
                    .replace(original, replacement)
                    .encode()
                )
                catalog = json.loads(catalog_bytes())
                catalog["producer"]["workflow_sha256"] = (
                    f"sha256:{hashlib.sha256(workflow).hexdigest()}"
                )

                def fetch(repository: str, path: str, commit: str) -> bytes:
                    if (repository, path, commit) == (
                        REPOSITORY,
                        CATALOG_PATH,
                        BASE,
                    ):
                        return json.dumps(catalog).encode()
                    if repository == REPOSITORY and path == WORKFLOW_PATH:
                        return workflow
                    return default_fetch(repository, path, commit)

                self.assert_invalid(
                    applicable_evidence(),
                    "not the exact pinned central reusable caller",
                    fetch=fetch,
                )

    def test_observations_bind_phase_case_dimension_and_exact_value(self) -> None:
        evidence = applicable_evidence()
        evidence["operations"][0]["public_status"]["before"]["evidence"] = [
            observation_reference("after", "public_status")
        ]
        self.assert_invalid(evidence, "exact reviewed_base commit")

        self.assert_invalid(
            applicable_evidence(),
            "observation value does not match",
            **artifact_with_after({"public_status": "HTTP 500"}),
        )

    def test_before_artifact_cannot_use_an_inventory_pre_change_revision(self) -> None:
        evidence = applicable_evidence()

        def wrong_base_run(repository: str, run_id: int) -> dict[str, object]:
            run = successful_run(repository, run_id)
            if run_id == 12344:
                run["head_sha"] = OLD
            return run

        self.assert_invalid(
            evidence,
            "exact reviewed_base commit",
            fetch_run=wrong_base_run,
        )

    def test_noop_test_hand_authored_head_observation_and_unrelated_run_fail(
        self,
    ) -> None:
        evidence = applicable_evidence()
        evidence["operations"][0]["public_status"]["after"]["evidence"] = [
            f"observation:{REPOSITORY}@{HEAD}:tests/contracts/after.json#"
            f"{CASE_ID}.public_status.after"
        ]

        def hand_authored(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == (
                REPOSITORY,
                "tests/contracts/after.json",
                HEAD,
            ):
                return observation_bytes("after")
            return default_fetch(repository, path, commit)

        def unrelated_run(repository: str, run_id: int) -> dict[str, object]:
            run = successful_run(repository, run_id)
            if run_id == 12345:
                run["path"] = ".github/workflows/unrelated-green.yml"
            return run

        self.assert_invalid(
            evidence,
            "strict test, artifact-observation",
            fetch=hand_authored,
            fetch_run=unrelated_run,
        )

        evidence = applicable_evidence()
        self.assert_invalid(
            evidence,
            "workflow does not match the catalog",
            fetch_run=unrelated_run,
        )

    def test_after_artifact_requires_exact_job_digest_zip_and_provenance(self) -> None:
        evidence = applicable_evidence()
        self.assert_invalid(
            evidence,
            "producer job must be unique",
            fetch_jobs=jobs_with_after(
                [
                    {
                        "name": "unrelated",
                        "status": "completed",
                        "conclusion": "success",
                        "run_attempt": 2,
                    }
                ]
            ),
        )
        self.assert_invalid(
            evidence,
            "producer job must succeed in this attempt",
            fetch_jobs=jobs_with_after(
                [
                    {
                        "name": JOB_NAME,
                        "status": "completed",
                        "conclusion": "success",
                        "run_id": 999,
                        "head_sha": HEAD,
                    }
                ]
            ),
        )
        for missing_step in (PRODUCE_STEP_NAME, UPLOAD_STEP_NAME):
            with self.subTest(missing_step=missing_step):
                job = successful_jobs(REPOSITORY, 12345, 2)[0]
                job["steps"] = [
                    step for step in job["steps"] if step["name"] != missing_step
                ]
                self.assert_invalid(
                    evidence,
                    "required producer step.*must be unique",
                    fetch_jobs=jobs_with_after([job]),
                )
        self.assert_invalid(
            evidence,
            "artifact workflow_run must be an object",
            **artifact_with_archive(
                artifact_zip(),
                after_metadata={
                    "id": 456,
                    "name": ARTIFACT_NAME,
                    "expired": False,
                    "digest": "sha256:" + "0" * 64,
                },
            ),
        )
        invalid_digest = artifact_metadata(artifact_zip())
        invalid_digest["digest"] = None
        self.assert_invalid(
            evidence,
            "artifact digest",
            **artifact_with_archive(artifact_zip(), after_metadata=invalid_digest),
        )
        self.assert_invalid(
            evidence,
            "digest does not match",
            **artifact_with_archive(
                artifact_zip() + b"tampered",
                after_metadata=artifact_metadata(artifact_zip()),
            ),
        )
        workflow_archive = artifact_zip()
        self.assert_invalid(
            evidence,
            "workflow_run id does not match",
            **artifact_with_archive(
                workflow_archive,
                after_metadata={
                    "id": 456,
                    "name": ARTIFACT_NAME,
                    "expired": False,
                    "digest": (
                        f"sha256:{hashlib.sha256(workflow_archive).hexdigest()}"
                    ),
                    "workflow_run": {
                        "id": 999,
                        "head_sha": HEAD,
                        "head_branch": "feature/probe",
                        "repository_id": 99,
                        "head_repository_id": 99,
                    },
                },
            ),
        )
        for field in (
            "head_sha",
            "head_branch",
            "repository_id",
            "head_repository_id",
        ):
            with self.subTest(workflow_run_field=field):
                metadata = artifact_metadata(workflow_archive)
                del metadata["workflow_run"][field]
                self.assert_invalid(
                    evidence,
                    f"workflow_run {'head' if field == 'head_sha' else field}",
                    **artifact_with_archive(workflow_archive, after_metadata=metadata),
                )
        metadata = artifact_metadata(workflow_archive)
        metadata["workflow_run"]["head_branch"] = "main"
        self.assert_invalid(
            evidence,
            "workflow_run head_branch does not match the Actions run",
            **artifact_with_archive(workflow_archive, after_metadata=metadata),
        )

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr("../feature-regression-observations.json", b"{}")
        unsafe = output.getvalue()
        self.assert_invalid(
            evidence,
            "ZIP topology is unsafe",
            **artifact_with_archive(unsafe),
        )

        output = io.BytesIO()
        special = zipfile.ZipInfo(OBSERVATION_MEMBER)
        special.create_system = 3
        special.external_attr = 0o010644 << 16
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr(special, observation_bytes("after"))
        special_archive = output.getvalue()
        self.assert_invalid(
            evidence,
            "ZIP topology is unsafe",
            **artifact_with_archive(special_archive),
        )

        document = json.loads(observation_bytes("after"))
        document["producer"]["run_attempt"] = 1
        noncanonical = json.dumps(document, indent=2).encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr(OBSERVATION_MEMBER, noncanonical)
        archive = output.getvalue()
        self.assert_invalid(
            evidence,
            "observation JSON must be canonical",
            **artifact_with_archive(archive),
        )

    def test_after_artifact_binds_subject_provenance_and_runtime_receipt(self) -> None:
        evidence = applicable_evidence()
        producer_mutations = (
            ("subject_path", ".github/feature-regression/other.py"),
            ("subject_sha256", "sha256:" + "3" * 64),
            ("subject_runtime", "direct"),
            ("subject_args", ["--forged"]),
            ("subject_env", {"MODE": "forged"}),
            ("runtime_image", "python:3.12-alpine@sha256:" + "4" * 64),
        )
        for field, value in producer_mutations:
            with self.subTest(producer_field=field):
                document = json.loads(observation_bytes("after"))
                document["producer"][field] = value
                archive = artifact_document_zip(document)
                self.assert_invalid(
                    evidence,
                    "artifact provenance does not match",
                    **artifact_with_archive(archive),
                )

    def test_artifact_phase_event_branch_and_expiry_fail_closed(self) -> None:
        evidence = applicable_evidence()

        def altered_run(target_run: int, field: str, value: object):
            def fetch(repository: str, run_id: int) -> dict[str, object]:
                run = successful_run(repository, run_id)
                if run_id == target_run:
                    run[field] = value
                return run

            return fetch

        cases = (
            (12345, "event", "push", "after artifact must come from"),
            (12344, "event", "pull_request", "before artifact must come from"),
            (12344, "head_branch", "feature/x", "on main"),
        )
        for run_id, field, value, expected in cases:
            with self.subTest(run_id=run_id, field=field):
                self.assert_invalid(
                    applicable_evidence(),
                    expected,
                    fetch_run=altered_run(run_id, field, value),
                )

        after_archive = artifact_zip()
        expired = artifact_metadata(after_archive)
        expired["expired"] = True
        self.assert_invalid(
            applicable_evidence(),
            "artifact must be unexpired",
            **artifact_with_archive(after_archive, after_metadata=expired),
        )

        wrong_phase = json.loads(observation_bytes("after"))
        wrong_phase["phase"] = "before"
        wrong_phase["producer"]["phase"] = "before"
        self.assert_invalid(
            applicable_evidence(),
            "artifact provenance does not match|phase metadata does not match",
            **artifact_with_archive(artifact_document_zip(wrong_phase)),
        )

        receipt_mutations = (
            ("subject_path", ".github/feature-regression/other.py"),
            ("subject_sha256", "sha256:" + "3" * 64),
            ("runtime", "direct"),
            ("arguments", ["--forged"]),
            ("environment", {"TZ": "UTC"}),
            ("exit_code", 1),
            ("runtime_image", "python:3.12-alpine@sha256:" + "4" * 64),
        )
        for field, value in receipt_mutations:
            with self.subTest(receipt_field=field):
                document = json.loads(observation_bytes("after"))
                document["runtime_receipt"][field] = value
                archive = artifact_document_zip(document)
                self.assert_invalid(
                    evidence,
                    "runtime receipt.*does not match|successful invocation",
                    **artifact_with_archive(archive),
                )

    def test_test_reference_requires_strict_utf8_and_existing_token(self) -> None:
        for content, expected in (
            (b"\xff", "not strict UTF-8"),
            (b"def a_different_test(): pass", "does not exist in exact source"),
        ):
            with self.subTest(expected=expected):

                def fetch(repository: str, path: str, commit: str) -> bytes:
                    if path == "tests/test_api.py":
                        return content
                    return default_fetch(repository, path, commit)

                self.assert_invalid(applicable_evidence(), expected, fetch=fetch)

    def test_artifact_run_must_be_successful_and_at_an_allowed_revision(self) -> None:
        cases = (
            (
                {
                    "status": "in_progress",
                    "conclusion": None,
                    "head_sha": HEAD,
                    "run_attempt": 2,
                    "path": WORKFLOW_PATH,
                },
                "completed successfully",
            ),
            (
                {
                    "status": "completed",
                    "conclusion": "failure",
                    "head_sha": HEAD,
                    "run_attempt": 2,
                    "path": WORKFLOW_PATH,
                },
                "completed successfully",
            ),
            (
                {
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "d" * 40,
                    "run_attempt": 2,
                    "path": WORKFLOW_PATH,
                },
                "exact reviewed_head",
            ),
        )
        for run, expected in cases:
            with self.subTest(run=run):

                def fetch_run(repository: str, run_id: int, value=run):
                    if run_id == 12344:
                        return successful_run(repository, run_id)
                    return value

                self.assert_invalid(
                    applicable_evidence(),
                    expected,
                    fetch_run=fetch_run,
                )

    def test_inventory_sources_are_fetched_even_without_cross_boundary(self) -> None:
        def missing_inventory(repository: str, path: str, commit: str) -> bytes:
            raise EvidenceError("inventory exact tuple missing")

        self.assert_invalid(
            applicable_evidence(),
            "inventory exact tuple missing",
            fetch=missing_inventory,
        )

    def test_external_inventory_forces_cross_boundary(self) -> None:
        evidence = applicable_evidence()
        evidence["inventory_sources"].append(
            {
                "repository": "ElevenID/consumer",
                "path": "contract/api.json",
                "commit": "d" * 40,
                "phase": "post_change",
            }
        )

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if path == "tests/test_api.py":
                return b"def test_approval_provider_failure(): pass"
            return b"{}"

        self.assert_invalid(
            evidence, "cross_boundary.applies must be true", fetch=fetch
        )

    def test_external_moved_owner_forces_cross_boundary(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["safe_server_diagnostic"]
        dimension["disposition"] = "moved"
        dimension["moved_owner"] = "ElevenID/consumer"
        dimension["test_mapping"] = {"before": BASE_TEST, "after": TEST}
        self.assert_invalid(evidence, "cross_boundary.applies must be true")

    def test_cross_boundary_requires_inventory_membership_and_current_head(
        self,
    ) -> None:
        content = b'{"operation":"approve"}'
        digest = canonical_json_digest(content)
        current_old = (REPOSITORY, "contract/api.json", OLD)
        external = ("ElevenID/consumer", "contract/api.json", "d" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "pre_change" if item == current_old else "post_change",
            }
            for item in (current_old, external)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": digest,
                }
                for item in (current_old, external)
            ],
        }

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if path == "tests/test_api.py":
                return b"def test_approval_provider_failure(): pass"
            return content

        self.assert_invalid(
            evidence, "current repository at reviewed_head", fetch=fetch
        )
        evidence["cross_boundary"]["sources"][1]["path"] = "other/api.json"
        self.assert_invalid(
            evidence, "exact tuple declared in inventory_sources", fetch=fetch
        )

    def test_cross_boundary_rejects_case_only_duplicate_repository_tuple(self) -> None:
        content = b'{"operation":"approve"}'
        digest = canonical_json_digest(content)
        current = (REPOSITORY, "contract/api.json", HEAD)
        external = ("ElevenID/consumer", "contract/api.json", "d" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": current[0],
                "path": current[1],
                "commit": current[2],
                "phase": "post_change",
            },
            {
                "repository": external[0],
                "path": external[1],
                "commit": external[2],
                "phase": "post_change",
            },
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": current[0],
                    "path": current[1],
                    "commit": current[2],
                    "sha256": digest,
                },
                {
                    "repository": current[0].lower(),
                    "path": current[1],
                    "commit": current[2],
                    "sha256": digest,
                },
                {
                    "repository": external[0],
                    "path": external[1],
                    "commit": external[2],
                    "sha256": digest,
                },
            ],
        }

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if path == "tests/test_api.py":
                return b"def test_approval_provider_failure(): pass"
            return content

        self.assert_invalid(
            evidence, "cross_boundary.sources must contain unique tuples", fetch=fetch
        )

    def test_cross_boundary_current_head_contract_must_be_post_change(self) -> None:
        content = b'{"operation":"approve"}'
        digest = canonical_json_digest(content)
        current = (REPOSITORY, "contract/api.json", HEAD)
        external = ("ElevenID/consumer", "contract/api.json", "d" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "pre_change" if item == current else "post_change",
            }
            for item in (current, external)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": digest,
                }
                for item in (current, external)
            ],
        }

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if path == "tests/test_api.py":
                return b"def test_approval_provider_failure(): pass"
            return content

        self.assert_invalid(
            evidence,
            "current repository at reviewed_head as a post_change inventory source",
            fetch=fetch,
        )

    def test_production_evidence_cannot_blanket_dimensions_or_surfaces_as_na(
        self,
    ) -> None:
        evidence = applicable_evidence()
        evidence["operations"][0]["public_message"] = {
            "disposition": "not_applicable",
            "rationale": "No public message.",
        }
        self.assert_invalid(evidence, "not_applicable is forbidden")

        evidence = applicable_evidence()
        evidence["surface_coverage"]["failure_semantics"] = {
            "not_applicable": "Claimed absent."
        }
        self.assert_invalid(evidence, "not_applicable is forbidden")

    def test_structured_not_exposed_values_are_valid_evidence(self) -> None:
        evidence = applicable_evidence()
        evidence["operations"][0]["public_status"] = comparison("not_exposed")

        self.validate(
            evidence,
            **artifact_with_after(
                {"public_status": "not_exposed"},
                before_overrides={"public_status": "not_exposed"},
            ),
        )

    def test_intentional_change_requires_actual_maintain_or_admin_permission(
        self,
    ) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["public_message"]
        dimension["disposition"] = "intentionally_changed"
        dimension["after"]["value"] = "Replacement approval message"
        dimension["decision"] = {
            "approved_by": "reviewer",
            "authority_role": "repository_maintainer",
            "decision_ref": (
                f"decision:{REPOSITORY}@{BASE}:decisions/feature-loss.json#"
                "approval-message"
            ),
            "compatibility_impact": "Wording changes.",
            "replacement_behavior": "Operation remains specific.",
            "breaking_loss": False,
            "before_value": "Credential approval failed",
            "after_value": "Replacement approval message",
        }
        for permission, role_name in (("write", "write"), ("triage", "triage")):
            with self.subTest(permission=permission, role_name=role_name):
                self.assert_invalid(
                    evidence,
                    "maintain/admin permission and role_name",
                    authority=lambda _login, permission=permission, role_name=role_name: {
                        "permission": permission,
                        "role_name": role_name,
                    },
                )
        for permission, role_name in (
            ("write", "maintain"),
            ("maintain", "maintain"),
            ("admin", "admin"),
        ):
            with self.subTest(permission=permission, role_name=role_name):
                self.validate(
                    evidence,
                    authority=lambda _login, permission=permission, role_name=role_name: {
                        "permission": permission,
                        "role_name": role_name,
                    },
                    **artifact_with_after(
                        {"public_message": "Replacement approval message"}
                    ),
                    fetch_decision=lambda _url: decision_bytes(
                        impact="Wording changes.",
                        replacement="Operation remains specific.",
                    ),
                )

        self.assert_invalid(
            evidence,
            "maintain/admin permission and role_name",
            authority=lambda _login: {"permission": "admin", "role_name": "write"},
        )
        self.assert_invalid(
            evidence,
            "maintain/admin permission and role_name",
            authority=lambda _login: {
                "permission": "write",
                "role_name": "admin",
            },
        )

    def test_decision_record_binds_scope_values_digests_and_approver(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["public_message"]
        dimension["disposition"] = "intentionally_changed"
        dimension["after"]["value"] = "Replacement approval message"
        dimension["decision"] = {
            "approved_by": "reviewer",
            "authority_role": "repository_maintainer",
            "decision_ref": (
                f"decision:{REPOSITORY}@{BASE}:decisions/feature-loss.json#"
                "approval-message"
            ),
            "compatibility_impact": "Wording changes.",
            "replacement_behavior": "Operation remains specific.",
            "breaking_loss": False,
            "before_value": "Credential approval failed",
            "after_value": "Replacement approval message",
        }
        for field, value, expected in (
            ("approved_by", "someone-else", "approved_by does not match"),
            ("before_sha256", "sha256:" + "0" * 64, "before_sha256 does not match"),
        ):
            with self.subTest(field=field):
                record = json.loads(
                    decision_bytes(
                        impact="Wording changes.",
                        replacement="Operation remains specific.",
                    )
                )
                record["decisions"][0][field] = value
                self.assert_invalid(
                    evidence,
                    expected,
                    **artifact_with_after(
                        {"public_message": "Replacement approval message"}
                    ),
                    fetch_decision=lambda _url, payload=record: json.dumps(
                        payload
                    ).encode(),
                )

    def test_decision_record_must_exist_and_url_must_be_clean(self) -> None:
        evidence = applicable_evidence()
        dimension = evidence["operations"][0]["public_message"]
        dimension["disposition"] = "intentionally_changed"
        dimension["after"]["value"] = "Replacement approval message"
        dimension["decision"] = {
            "approved_by": "reviewer",
            "authority_role": "repository_maintainer",
            "decision_ref": (
                f"decision:{REPOSITORY}@{BASE}:decisions/feature-loss.json#"
                "approval-message"
            ),
            "compatibility_impact": "Wording changes.",
            "replacement_behavior": "Operation remains specific.",
            "breaking_loss": False,
            "before_value": "Credential approval failed",
            "after_value": "Replacement approval message",
        }
        self.assert_invalid(
            evidence,
            "decision record missing",
            fetch_decision=lambda _url: (_ for _ in ()).throw(
                EvidenceError("decision record missing")
            ),
        )
        dimension["decision"]["decision_ref"] = (
            f"decision:{REPOSITORY}@{HEAD}:decisions/feature-loss.json#approval-message"
        )
        self.assert_invalid(evidence, "reviewed repository at reviewed_base")

    def test_recursive_sanitizer_rejects_control_secrets_urls_and_pii(self) -> None:
        bad_values = (
            ("line one\nline two", "control character"),
            ("Authorization: Bearer abc", "authorization value"),
            ("access_token=abc", "secret assignment"),
            ("token=abc", "secret assignment"),
            ('{"password":"hunter2"}', "secret assignment"),
            ('{"client_secret":"ordinarysecretvalue"}', "secret assignment"),
            ('{"authorization":"Basic dXNlcjpwYXNz"}', "authorization value"),
            ('password: "hunter2"', "secret assignment"),
            ("-----BEGIN PRIVATE KEY-----", "private-key material"),
            ("contact admin@example.com", "email-shaped"),
            ("Call 303-555-0199", "phone-shaped"),
            ("https://user:pass@example.com/path", "userinfo, query, or fragment"),
            ("See https://example.com/path?q=secret", "userinfo, query, or fragment"),
            ("See https://example.com/secret/value", "secret-like URL path"),
            ("See https://example.com/%74oken/value", "secret-like URL path"),
            ("See https://example.com/client-token/value", "secret-like URL path"),
            ("See https://example.com/%2573ecret/value", "secret-like URL path"),
            ("ghp_1234567890abcdef", "standalone secret"),
            ("github_pat_1234567890", "standalone secret"),
            ("sk-1234567890", "standalone secret"),
            ("xoxb-1234567890", "standalone secret"),
        )
        for value, expected in bad_values:
            with self.subTest(value=value):
                evidence = applicable_evidence()
                evidence["residual_risks"] = [value]
                self.assert_invalid(evidence, expected)

        evidence = applicable_evidence()
        evidence["operations"][0]["safe_server_diagnostic"]["before"]["value"] = {
            "api_key=abc": "unsafe"
        }
        self.assert_invalid(evidence, "secret assignment")

        for key, value, expected in (
            ("password", "hunter2", "secret assignment"),
            ("client_secret", "ordinarysecretvalue", "secret assignment"),
            ("authorization", "Basic dXNlcjpwYXNz", "secret assignment"),
        ):
            with self.subTest(mapping_key=key):
                evidence = applicable_evidence()
                evidence["operations"][0]["safe_server_diagnostic"]["before"][
                    "value"
                ] = {key: value}
                self.assert_invalid(evidence, expected)

        evidence = applicable_evidence()
        evidence["operations"][0]["safe_server_diagnostic"] = comparison(
            {"api_key": "not_exposed"}, "safe_server_diagnostic"
        )

        override = {"safe_server_diagnostic": {"api_key": "not_exposed"}}
        self.validate(
            evidence,
            **artifact_with_after(
                override,
                before_overrides=override,
            ),
        )

    def test_extract_rejects_duplicate_keys_and_nonfinite_constants(self) -> None:
        for payload, expected in (
            ('{"schema":"a","schema":"b"}', "duplicate key"),
            ('{"value":NaN}', "prohibited constant"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(EvidenceError, expected):
                    extract_evidence(f"{MARKER}\n```json\n{payload}\n```")

    def test_github_read_apis_fail_closed_on_non_file_and_pull_decision(self) -> None:
        client = GitHubClient(
            api_url="https://api.github.test", repository=REPOSITORY, token="token"
        )
        with mock.patch.object(client, "_get", return_value={"type": "dir"}):
            with self.assertRaisesRegex(EvidenceError, "is not a file"):
                client.content(REPOSITORY, "contract/api.json", HEAD)
        with self.assertRaisesRegex(EvidenceError, "decision:<owner/repo>"):
            client.decision("https://github.com/ElevenID/example/issues/10")

    def test_github_run_and_permission_reads_use_exact_repository(self) -> None:
        client = GitHubClient(
            api_url="https://api.github.test", repository=REPOSITORY, token="token"
        )
        responses = [
            {"status": "completed", "conclusion": "success", "head_sha": HEAD},
            {"permission": "write", "role_name": "maintain"},
        ]
        with mock.patch.object(client, "_get", side_effect=responses) as get:
            self.assertEqual("success", client.run(REPOSITORY, 123)["conclusion"])
            self.assertEqual("maintain", client.permission("reviewer")["role_name"])
        self.assertEqual(
            [
                mock.call(f"/repos/{REPOSITORY}/actions/runs/123"),
                mock.call(f"/repos/{REPOSITORY}/collaborators/reviewer/permission"),
            ],
            get.call_args_list,
        )

    def test_artifact_download_strips_authorization_after_trusted_redirect(
        self,
    ) -> None:
        class Response:
            def __init__(self, code: int, headers=None, payload: bytes = b"") -> None:
                self.code = code
                self.headers = headers or {}
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self) -> int:
                return self.code

            def read(self, _limit: int) -> bytes:
                return self.payload

        class Opener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout: int):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    return Response(
                        302,
                        {
                            "Location": (
                                "https://productionresultssa0.blob.core.windows.net/"
                                "actions/results.zip?sig=signed"
                            )
                        },
                    )
                return Response(200, payload=b"zip bytes")

        client = GitHubClient(
            api_url="https://api.github.test", repository=REPOSITORY, token="token"
        )
        opener = Opener()
        with mock.patch("urllib.request.build_opener", return_value=opener):
            self.assertEqual(b"zip bytes", client.download_artifact(REPOSITORY, 456))
        api_request = opener.requests[0][0]
        storage_request = opener.requests[1][0]
        self.assertEqual("Bearer token", api_request.get_header("Authorization"))
        self.assertEqual("2026-03-10", api_request.get_header("X-github-api-version"))
        self.assertIsNone(storage_request.get_header("Authorization"))
        self.assertIsNone(storage_request.get_header("X-github-api-version"))

    def test_rejects_unresolved_blocking_findings(self) -> None:
        evidence = applicable_evidence()
        evidence["findings"] = [
            {
                "severity": "blocking",
                "status": "accepted",
                "summary": "Approval text regressed.",
                "evidence": [TEST],
            }
        ]
        self.assert_invalid(evidence, "unresolved blocking")

    def test_requires_exact_ten_surface_coverage(self) -> None:
        evidence = applicable_evidence()
        del evidence["surface_coverage"]["failure_semantics"]
        self.assert_invalid(evidence, "ten contract surfaces")

    def test_canonical_json_v1_normalizes_key_order_and_whitespace(self) -> None:
        left = canonical_json_digest(b'{"b": 2, "a": [1, true]}')
        right = canonical_json_digest(b'{\n  "a":[1,true],"b":2\n}')
        self.assertEqual(left, right)

    def test_cross_boundary_fetches_exact_commits_and_matches_real_fixtures(
        self,
    ) -> None:
        content = b'{"operation":"approve","status":502}'
        digest = canonical_json_digest(content)
        first = (REPOSITORY, "contract/api.json", HEAD)
        second = ("ElevenID/consumer", "contract/api.json", "2" * 40)
        fixtures = {first: content, second: b'{ "status": 502, "operation":"approve" }'}
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "post_change",
            }
            for item in (first, second)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": digest,
                }
                for item in (first, second)
            ],
        }

        def fetch(*key: str) -> bytes:
            if key in fixtures:
                return fixtures[key]
            return default_fetch(*key)

        self.validate(evidence, fetch=fetch)

    def test_cross_boundary_allows_same_path_at_distinct_declared_commits(self) -> None:
        content = b'{"status":502}'
        digest = canonical_json_digest(content)
        source = {
            "repository": REPOSITORY,
            "path": "contract/api.json",
            "commit": HEAD,
            "sha256": digest,
        }
        evidence = applicable_evidence()
        second = copy.deepcopy(source)
        second["commit"] = "2" * 40
        evidence["inventory_sources"] = [
            {
                **{key: item[key] for key in ("repository", "path", "commit")},
                "phase": "post_change",
            }
            for item in (source, second)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [source, second],
        }

        def fetch(*key: str) -> bytes:
            if key in {
                (REPOSITORY, "contract/api.json", HEAD),
                (REPOSITORY, "contract/api.json", "2" * 40),
            }:
                return content
            return default_fetch(*key)

        self.validate(evidence, fetch=fetch)

    def test_cross_boundary_must_cover_every_external_inventory_repository(
        self,
    ) -> None:
        content = b'{"status":502}'
        digest = canonical_json_digest(content)
        current = (REPOSITORY, "contract/api.json", HEAD)
        first_external = ("ElevenID/consumer-a", "contract/api.json", "1" * 40)
        second_external = ("ElevenID/consumer-b", "contract/api.json", "2" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "post_change",
            }
            for item in (current, first_external, second_external)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": digest,
                }
                for item in (current, first_external)
            ],
        }
        self.assert_invalid(
            evidence,
            "omit canonical contract sources for repositories.*consumer-b",
            fetch=lambda *_: content,
        )

    def test_cross_boundary_allows_legacy_inventory_beside_one_contract_source(
        self,
    ) -> None:
        content = b'{"status":502}'
        digest = canonical_json_digest(content)
        current = (REPOSITORY, "contract/api.json", HEAD)
        external_one = ("ElevenID/consumer", "contract/api.json", "1" * 40)
        external_two = ("ElevenID/consumer", "contract/errors.json", "2" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "post_change",
            }
            for item in (current, external_one, external_two)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": digest,
                }
                for item in (current, external_one)
            ],
        }

        def fetch(repository: str, path: str, commit: str) -> bytes:
            if (repository, path, commit) == external_two:
                return b"def legacy_python_test(): pass"
            if (repository, path, commit) in {current, external_one}:
                return content
            return default_fetch(repository, path, commit)

        self.validate(evidence, fetch=fetch)

    def test_cross_boundary_rejects_false_commit_tuple_like_827(self) -> None:
        content = b'{"status":502}'
        digest = canonical_json_digest(content)
        real = (REPOSITORY, "contract/api.json", HEAD)
        false = ("ElevenID/consumer", "contract/api.json", "9" * 40)
        evidence = applicable_evidence()
        evidence["inventory_sources"] = [
            {
                "repository": key[0],
                "path": key[1],
                "commit": key[2],
                "phase": "post_change",
            }
            for key in (real, false)
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": digest,
            "sources": [
                {
                    "repository": key[0],
                    "path": key[1],
                    "commit": key[2],
                    "sha256": digest,
                }
                for key in (real, false)
            ],
        }

        def fetch(*key: str) -> bytes:
            if key != real:
                raise EvidenceError("exact commit/path was not found")
            return content

        self.assert_invalid(evidence, "exact commit/path was not found", fetch=fetch)

    def test_cross_boundary_rejects_false_digest(self) -> None:
        expected = f"sha256:{hashlib.sha256(b'not canonical').hexdigest()}"
        evidence = applicable_evidence()
        inventory = [
            (REPOSITORY, "contract/api.json", HEAD),
            ("ElevenID/repo-2", "contract/api.json", "2" * 40),
        ]
        evidence["inventory_sources"] = [
            {
                "repository": item[0],
                "path": item[1],
                "commit": item[2],
                "phase": "post_change",
            }
            for item in inventory
        ]
        evidence["cross_boundary"] = {
            "applies": True,
            "method": CANONICAL_JSON_METHOD,
            "common_sha256": expected,
            "sources": [
                {
                    "repository": item[0],
                    "path": item[1],
                    "commit": item[2],
                    "sha256": expected,
                }
                for item in inventory
            ],
        }
        self.assert_invalid(
            evidence,
            "content digest .* does not equal",
            fetch=lambda *_: b'{"status":502}',
        )

    def test_latest_marked_comment_is_authoritative(self) -> None:
        stale = applicable_evidence()
        stale["reviewed_head"] = "d" * 40
        selected, result = validate_latest_comment(
            [comment(stale), comment(applicable_evidence())],
            repository=REPOSITORY,
            current_base=BASE,
            current_head=HEAD,
            trusted_policy_ref=FUTURE_APPROVED_REPAIR_SHA,
            changed_files=PRODUCTION_FILES,
            fetch_content=default_fetch,
            fetch_run=successful_run,
            fetch_jobs=successful_jobs,
            fetch_artifacts=successful_artifacts,
            download_artifact=successful_download,
            authority_resolver=lambda _login: {
                "permission": "maintain",
                "role_name": "maintain",
            },
            decision_fetcher=lambda _url: b"{}",
        )
        self.assertEqual(HEAD, result["reviewed_head"])
        self.assertEqual(comment(applicable_evidence())["body"], selected["body"])

    def test_untrusted_marker_cannot_override_authorized_evidence(self) -> None:
        untrusted = comment(applicable_evidence(), author="outsider")
        untrusted["author_association"] = "NONE"
        selected, result = validate_latest_comment(
            [comment(applicable_evidence()), untrusted],
            repository=REPOSITORY,
            current_base=BASE,
            current_head=HEAD,
            trusted_policy_ref=FUTURE_APPROVED_REPAIR_SHA,
            changed_files=PRODUCTION_FILES,
            fetch_content=default_fetch,
            fetch_run=successful_run,
            fetch_jobs=successful_jobs,
            fetch_artifacts=successful_artifacts,
            download_artifact=successful_download,
            authority_resolver=lambda _login: {
                "permission": "maintain",
                "role_name": "maintain",
            },
            decision_fetcher=lambda _url: b"{}",
        )
        self.assertEqual("reviewer", selected["user"]["login"])
        self.assertEqual(HEAD, result["reviewed_head"])

    def test_extract_rejects_invalid_marked_json(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "evidence JSON is invalid"):
            extract_evidence(f"{MARKER}\n```json\n{{broken\n```")

    def test_v1_marker_is_rejected_instead_of_downgraded(self) -> None:
        old_marker = "<!-- elevenid-feature-regression-review:v1 -->"
        payload = json.dumps(applicable_evidence())
        with self.assertRaisesRegex(EvidenceError, "marker is missing"):
            extract_evidence(f"{old_marker}\n```json\n{payload}\n```")

    def test_pull_request_event_uses_fetched_current_metadata(self) -> None:
        pull = {
            "number": 7,
            "state": "open",
            "base": {"ref": "main", "sha": BASE},
            "head": {"sha": HEAD},
        }
        event = {"number": 7, "pull_request": {"head": {"sha": HEAD}}}
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request"}):
            self.assertEqual(
                [ReviewTarget(7, BASE, HEAD)],
                review_targets(event, FakeClient({7: pull})),
            )

    def test_merge_group_validates_all_associated_open_queue_prs(self) -> None:
        group_head = "f" * 40
        group_base = "e" * 40
        pulls = {
            101: {
                "number": 101,
                "state": "open",
                "base": {"ref": "main", "sha": BASE},
                "head": {"sha": "1" * 40},
            },
            102: {
                "number": 102,
                "state": "open",
                "base": {"ref": "main", "sha": BASE},
                "head": {"sha": "2" * 40},
            },
        }
        associated = [pulls[101], pulls[102]]
        event = {
            "merge_group": {
                "head_sha": group_head,
                "base_sha": group_base,
                "head_ref": "refs/heads/gh-readonly-queue/main/pr-101-deadbeef",
                "base_ref": "refs/heads/main",
            }
        }
        client = FakeClient(pulls, associated)
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "merge_group"}):
            targets = review_targets(event, client)
        self.assertEqual(
            [
                ReviewTarget(101, group_base, "1" * 40),
                ReviewTarget(102, group_base, "2" * 40),
            ],
            targets,
        )
        self.assertEqual((group_base, group_head), client.comparison)


if __name__ == "__main__":
    unittest.main()
