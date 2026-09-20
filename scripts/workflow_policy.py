from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections.abc import Iterable

import yaml

SHA = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")
FEATURE_REVIEW_CALL = re.compile(
    r"^ElevenID/\.github/\.github/workflows/"
    r"feature-regression-review\.yml@(?P<sha>[0-9a-f]{40})$"
)
FEATURE_REVIEW_REUSABLE_FILE = "feature-regression-review.yml"
FEATURE_REVIEW_CALLER_FILE = "feature-regression-review-caller.yml"
APPROVED_REVISIONS_PATH = (
    pathlib.Path(__file__).parents[1]
    / "maintenance"
    / "feature-regression-approved-revisions.json"
)
EOL_NODE_VERSION = re.compile(
    r"(?m)^\s*node-version\s*:\s*['\"]?(?:18|20|22)(?:\.[0-9x.*-]+)?['\"]?\s*(?:#.*)?$"
)

# actions/checkout v4 runs on Node 20. Keep known obsolete SHAs explicit so
# callers receive a useful failure even though every Action is SHA-pinned.
EOL_ACTION_REVISIONS = {
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5": "actions/checkout v4",
}


def _load_feature_review_activation() -> tuple[str | None, frozenset[str]]:
    try:
        payload = json.loads(APPROVED_REVISIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot load trusted feature-review revisions: {error}"
        ) from error
    if not isinstance(payload, dict) or set(payload) != {
        "approved_revision",
        "enabled_repositories",
    }:
        raise RuntimeError("feature-review activation schema is invalid")
    revision = payload["approved_revision"]
    if revision is not None and (
        not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
    ):
        raise RuntimeError("feature-review approved revision is not null or a full SHA")
    repositories = payload["enabled_repositories"]
    repository_pattern = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    if not isinstance(repositories, list) or any(
        not isinstance(repository, str)
        or repository_pattern.fullmatch(repository) is None
        for repository in repositories
    ):
        raise RuntimeError("feature-review activation contains an invalid repository")
    normalized = [repository.casefold() for repository in repositories]
    if len(normalized) != len(set(normalized)):
        raise RuntimeError("feature-review activation contains duplicate repositories")
    return revision, frozenset(normalized)


(
    APPROVED_FEATURE_REVIEW_REVISION,
    ENABLED_FEATURE_REVIEW_REPOSITORIES,
) = _load_feature_review_activation()


class ActionsLoader(yaml.SafeLoader):
    """Load the GitHub Actions YAML dialect without treating `on` as boolean."""


for first, mappings in list(ActionsLoader.yaml_implicit_resolvers.items()):
    ActionsLoader.yaml_implicit_resolvers[first] = [
        (tag, regexp) for tag, regexp in mappings if tag != "tag:yaml.org,2002:bool"
    ]


def _walk(value: object, path: str, failures: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "uses" and isinstance(child, str):
                if not child.startswith("./") and not SHA.match(child):
                    failures.append(
                        f"{child_path}: action is not pinned to a full commit SHA: {child}"
                    )
            _walk(child, child_path, failures)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", failures)


def _check_feature_review_calls(value: object, path: str, failures: list[str]) -> None:
    if isinstance(value, dict):
        uses = value.get("uses")
        if isinstance(uses, str) and FEATURE_REVIEW_REUSABLE_FILE in uses:
            match = FEATURE_REVIEW_CALL.fullmatch(uses)
            if match is None:
                failures.append(
                    f"{path}.uses: feature-regression workflow call must use "
                    "ElevenID/.github at a literal full commit SHA"
                )
            else:
                inputs = value.get("with")
                policy_ref = (
                    inputs.get("policy-ref") if isinstance(inputs, dict) else None
                )
                if not isinstance(policy_ref, str) or not re.fullmatch(
                    r"[0-9a-f]{40}", policy_ref
                ):
                    failures.append(
                        f"{path}.with.policy-ref: feature-regression policy-ref "
                        "must be a literal full commit SHA"
                    )
                elif policy_ref != match.group("sha"):
                    failures.append(
                        f"{path}.with.policy-ref: policy-ref must equal the uses SHA"
                    )
                elif match.group("sha") != APPROVED_FEATURE_REVIEW_REVISION:
                    failures.append(
                        f"{path}.uses: feature-regression revision is not the "
                        "single trusted approved revision"
                    )
        for key, child in value.items():
            _check_feature_review_calls(child, f"{path}.{key}", failures)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_feature_review_calls(child, f"{path}[{index}]", failures)


def _check_exact_feature_review_job(
    job: object, path: str, failures: list[str]
) -> None:
    if not isinstance(job, dict):
        return
    uses = job.get("uses")
    match = FEATURE_REVIEW_CALL.fullmatch(uses) if isinstance(uses, str) else None
    if match is None:
        failures.append(
            f"{path}.uses: reserved caller must call ElevenID/.github at a "
            "literal full commit SHA"
        )
        return
    inputs = job.get("with")
    policy_ref = inputs.get("policy-ref") if isinstance(inputs, dict) else None
    if (
        not isinstance(policy_ref, str)
        or re.fullmatch(r"[0-9a-f]{40}", policy_ref) is None
    ):
        failures.append(
            f"{path}.with.policy-ref: feature-regression policy-ref must be a "
            "literal full commit SHA"
        )
    elif policy_ref != match.group("sha"):
        failures.append(f"{path}.with.policy-ref: policy-ref must equal the uses SHA")
    elif match.group("sha") != APPROVED_FEATURE_REVIEW_REVISION:
        failures.append(
            f"{path}.uses: feature-regression revision is not the single trusted "
            "approved revision"
        )


def _has_feature_review_call(value: object) -> bool:
    if isinstance(value, dict):
        uses = value.get("uses")
        return (
            isinstance(uses, str)
            and FEATURE_REVIEW_REUSABLE_FILE in uses
            or any(_has_feature_review_call(child) for child in value.values())
        )
    if isinstance(value, list):
        return any(_has_feature_review_call(child) for child in value)
    return False


def check_workflow(workflow: pathlib.Path) -> list[str]:
    failures: list[str] = []
    text = workflow.read_text(encoding="utf-8")
    try:
        document = yaml.load(text, Loader=ActionsLoader)
    except yaml.YAMLError as error:
        return [f"{workflow}: invalid YAML: {error}"]

    _walk(document, str(workflow), failures)
    _check_feature_review_calls(document, str(workflow), failures)
    has_feature_call = _has_feature_review_call(document)
    is_reserved_caller = workflow.name == FEATURE_REVIEW_CALLER_FILE
    is_feature_gate = workflow.name == FEATURE_REVIEW_REUSABLE_FILE or (
        isinstance(document, dict)
        and document.get("name") == "Reusable feature-regression review"
    )
    if is_feature_gate and not isinstance(document, dict):
        failures.append(
            f"{workflow}: feature-regression gate must be a workflow object"
        )
    elif is_feature_gate:
        triggers = document.get("on")
        if not isinstance(triggers, dict) or set(triggers) != {"workflow_call"}:
            failures.append(
                f"{workflow}: feature-regression gate must use only workflow_call"
            )
        expected_permissions = {
            "actions": "read",
            "contents": "read",
            "issues": "read",
            "pull-requests": "read",
        }
        if document.get("permissions") != expected_permissions:
            failures.append(
                f"{workflow}: feature-regression gate permissions must be "
                "exactly actions, contents, issues, and pull-requests read"
            )
        if re.search(r"(?m)^\s+[A-Za-z-]+\s*:\s*write\s*$", text):
            failures.append(
                f"{workflow}: feature-regression gate may not request write permission"
            )
    if has_feature_call or is_reserved_caller:
        expected_caller_permissions = {
            "actions": "read",
            "contents": "read",
            "issues": "read",
            "pull-requests": "read",
        }
        if (
            not isinstance(document, dict)
            or document.get("permissions") != expected_caller_permissions
        ):
            failures.append(
                f"{workflow}: feature-regression caller permissions must be exactly "
                "actions, contents, issues, and pull-requests read"
            )
        if workflow.name != FEATURE_REVIEW_CALLER_FILE:
            failures.append(
                f"{workflow}: feature-regression caller filename must be "
                f"{FEATURE_REVIEW_CALLER_FILE}"
            )
        if not isinstance(document, dict) or set(document) != {
            "name",
            "on",
            "permissions",
            "jobs",
        }:
            failures.append(
                f"{workflow}: feature-regression caller must use the exact root schema"
            )
        elif document.get("name") != "feature-regression-review":
            failures.append(
                f"{workflow}: feature-regression caller name must be "
                "feature-regression-review"
            )
        if isinstance(document, dict):
            expected_triggers = {
                "pull_request": {"branches": ["main"]},
                "merge_group": {"types": ["checks_requested"]},
            }
            if document.get("on") != expected_triggers:
                failures.append(
                    f"{workflow}: feature-regression caller triggers must be exact, "
                    "unfiltered pull_request main plus merge_group checks_requested"
                )
            jobs = document.get("jobs")
            if not isinstance(jobs, dict) or set(jobs) != {"feature-regression-review"}:
                failures.append(
                    f"{workflow}: feature-regression caller must contain only the exact "
                    "feature-regression-review job id"
                )
            else:
                job = jobs["feature-regression-review"]
                if not isinstance(job, dict) or set(job) != {"uses", "with"}:
                    failures.append(
                        f"{workflow}: feature-regression caller job may contain only "
                        "uses and with; skip/masking controls are prohibited"
                    )
                elif not isinstance(job.get("with"), dict) or set(job["with"]) != {
                    "policy-ref"
                }:
                    failures.append(
                        f"{workflow}: feature-regression caller with must contain only "
                        "policy-ref"
                    )
                if is_reserved_caller:
                    _check_exact_feature_review_job(
                        job,
                        f"{workflow}.jobs.feature-regression-review",
                        failures,
                    )
    checks = {
        r"(?m)^\s*pull_request_target\s*:": "pull_request_target is prohibited",
        r"(?m)^\s*permissions\s*:\s*write-all\s*$": "write-all permissions are prohibited",
    }
    required = "# elevenid:required" in text
    pull_request = bool(re.search(r"(?m)^\s*pull_request(?:_target)?\s*:", text))
    merge_group = bool(re.search(r"(?m)^\s*merge_group\s*:", text))
    if required:
        checks.update(
            {
                r"(?m)^\s*continue-on-error\s*:\s*true\s*$": "required workflows may not ignore failures",
                r"(?:\|\|\s*true|--exit-zero)": "failure-masking command found",
            }
        )
    if pull_request:
        checks[r"(?m)^\s*runs-on\s*:\s*(?:self-hosted|\[.*self-hosted.*\])\s*$"] = (
            "self-hosted runner is prohibited for pull requests"
        )
    if required and pull_request and not merge_group:
        failures.append(
            f"{workflow}: required pull-request workflows must handle merge_group"
        )
    if EOL_NODE_VERSION.search(text):
        failures.append(f"{workflow}: Node 18, 20, and 22 are unsupported; use Node 24")
    for revision, label in EOL_ACTION_REVISIONS.items():
        if revision in text:
            failures.append(
                f"{workflow}: {label} uses the unsupported Node 20 Action runtime"
            )
    for pattern, message in checks.items():
        if re.search(pattern, text):
            failures.append(f"{workflow}: {message}")
    return failures


def check_paths(
    paths: Iterable[pathlib.Path],
    *,
    repository: str,
    repository_root: pathlib.Path | None = None,
) -> list[str]:
    failures: list[str] = []
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        return ["current repository must be an explicit owner/repository name"]
    repository_root = repository_root or pathlib.Path.cwd()
    scanned: set[pathlib.Path] = set()
    for path in paths:
        workflows = path.glob("*.y*ml") if path.is_dir() else [path]
        for workflow in workflows:
            scanned.add(workflow.resolve())
            failures.extend(check_workflow(workflow))
    if repository.casefold() in ENABLED_FEATURE_REVIEW_REPOSITORIES:
        caller = repository_root / ".github" / "workflows" / FEATURE_REVIEW_CALLER_FILE
        if not caller.is_file():
            failures.append(f"{repository}: enabled feature review requires {caller}")
        elif caller.resolve() not in scanned:
            failures.append(
                f"{repository}: workflow-policy scan omitted the reserved feature-review caller"
            )
        else:
            # It was already validated above by reserved filename, even when its
            # uses value is absent or forged.
            pass
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--repository")
    args = parser.parse_args()
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        print(
            "ERROR: current repository is required via --repository or GITHUB_REPOSITORY",
            file=sys.stderr,
        )
        return 1
    failures = check_paths(args.paths, repository=repository)
    if failures:
        print("\n".join(f"ERROR: {failure}" for failure in failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
