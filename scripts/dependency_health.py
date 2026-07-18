from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import sys
from collections.abc import Iterable

import yaml

MANIFESTS = {"Cargo.toml", "package.json", "pyproject.toml", "pubspec.yaml"}
IGNORED_PARTS = {
    ".elevenid-quality",
    ".git",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
DECISIONS = {"retain", "upgrade", "replace", "fork", "remove"}
STATUSES = {"maintained", "watch", "blocked", "temporary-exception", "retiring"}


def _has_code_manifest(root: pathlib.Path) -> bool:
    for path in root.rglob("*"):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        if path.is_file() and path.name in MANIFESTS:
            return True
    return False


def _date(value: object) -> dt.date | None:
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def check_repository(root: pathlib.Path, today: dt.date | None = None) -> list[str]:
    root = root.resolve()
    health = root / "dependency-health.yml"
    if not health.exists():
        if _has_code_manifest(root):
            return [f"{health}: required for repositories with code manifests"]
        return []

    try:
        document = yaml.safe_load(health.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        return [f"{health}: invalid YAML: {error}"]

    failures: list[str] = []
    if not isinstance(document, dict) or document.get("version") != 1:
        return [f"{health}: version must be 1"]
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        return [f"{health}: dependencies must be a list"]

    required = {
        "package",
        "ecosystem",
        "owner",
        "upstream",
        "current",
        "target",
        "status",
        "decision",
        "advisories",
        "tracking-issue",
        "review-after",
        "rationale",
    }
    comparison_date = today or dt.date.today()
    for index, entry in enumerate(dependencies):
        label = f"{health}: dependencies[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{label} must be a mapping")
            continue
        missing = sorted(required - entry.keys())
        if missing:
            failures.append(f"{label} missing fields: {', '.join(missing)}")
            continue
        if entry["decision"] not in DECISIONS:
            failures.append(f"{label} has unsupported decision: {entry['decision']}")
        if entry["status"] not in STATUSES:
            failures.append(f"{label} has unsupported status: {entry['status']}")
        if not isinstance(entry["advisories"], list):
            failures.append(f"{label}.advisories must be a list")
        upstream = entry["upstream"]
        if not isinstance(upstream, str) or not upstream.startswith("https://"):
            failures.append(f"{label}.upstream must be an HTTPS URL")
        issue = entry["tracking-issue"]
        if issue and (not isinstance(issue, str) or not issue.startswith("https://")):
            failures.append(f"{label}.tracking-issue must be empty or an HTTPS URL")
        review_after = _date(entry["review-after"])
        if review_after is None:
            failures.append(f"{label}.review-after must be an ISO date")
        elif entry["status"] != "maintained" and review_after < comparison_date:
            failures.append(f"{label}.review-after expired on {review_after.isoformat()}")
        if not str(entry["rationale"]).strip():
            failures.append(f"{label}.rationale must not be empty")
    return failures


def check_paths(paths: Iterable[pathlib.Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        failures.extend(check_repository(path))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    failures = check_paths(args.paths)
    if failures:
        print("\n".join(f"ERROR: {failure}" for failure in failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
