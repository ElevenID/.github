from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections.abc import Iterable

import yaml

SHA = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")
STANDARD_RUNNERS = {"ubuntu-latest", "windows-latest", "macos-latest"}


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
            if key == "runs-on" and isinstance(child, str):
                if "${{" not in child and child not in STANDARD_RUNNERS:
                    failures.append(f"{child_path}: unapproved runner label: {child}")
            _walk(child, child_path, failures)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", failures)


def check_workflow(workflow: pathlib.Path) -> list[str]:
    failures: list[str] = []
    text = workflow.read_text(encoding="utf-8")
    try:
        document = yaml.load(text, Loader=ActionsLoader)
    except yaml.YAMLError as error:
        return [f"{workflow}: invalid YAML: {error}"]

    _walk(document, str(workflow), failures)
    checks = {
        r"(?m)^\s*pull_request_target\s*:": "pull_request_target is prohibited",
        r"(?m)^\s*permissions\s*:\s*write-all\s*$": "write-all permissions are prohibited",
        r"(?m)^\s*continue-on-error\s*:\s*true\s*$": "required workflows may not ignore failures",
        r"(?:\|\|\s*true|--exit-zero)": "failure-masking command found",
        r"(?m)^\s*runs-on\s*:\s*(?:self-hosted|\[.*self-hosted.*\])\s*$": "self-hosted runner is prohibited",
    }
    for pattern, message in checks.items():
        if re.search(pattern, text):
            failures.append(f"{workflow}: {message}")
    return failures


def check_paths(paths: Iterable[pathlib.Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        workflows = path.glob("*.y*ml") if path.is_dir() else [path]
        for workflow in workflows:
            failures.extend(check_workflow(workflow))
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
