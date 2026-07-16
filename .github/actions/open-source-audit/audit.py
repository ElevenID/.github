#!/usr/bin/env python3
"""Current-tree safety checks shared by ElevenID public repositories."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE")
TEXT_SUFFIXES = {
    "", ".c", ".cpp", ".css", ".dart", ".go", ".h", ".html", ".java",
    ".js", ".json", ".jsx", ".kt", ".kts", ".mdx", ".mjs", ".py",
    ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".yaml", ".yml",
}
SKIP_PARTS = {".git", "build", "dist", "node_modules", "target", "vendor"}
PRIVATE_MARKERS = (
    "github.com/ElevenID/marty-subscriptions",
    "github.com/ElevenID/product-catalog",
    "MARTY_SUBSCRIPTIONS_REF",
    "PRODUCT_CATALOG_TOKEN",
    "REPO_ACCESS_TOKEN",
    "MARTY_CORE_TOKEN",
    "SQUARE_ACCESS_TOKEN",
    "SQUARE_WEBHOOK_SIGNATURE_KEY",
    "connect.squareup.com",
)
STALE_MARKERS = ("github.com/burdettadam", "github.com/adamburdett", "github.com/your-org")
LARGER_RUNNER = re.compile(r"runs-on:\s*[^\n]*(?:xlarge|larger|(?:4|8|16|32|64)-core)", re.I)


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode() for item in result.stdout.split(b"\0") if item]


def audit(root: Path) -> list[str]:
    findings: list[str] = []
    if not any((root / name).is_file() for name in LICENSE_FILES):
        findings.append("missing repository license")

    for path in tracked_files(root):
        if not path.is_file() or SKIP_PARTS.intersection(path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if relative == ".github/actions/open-source-audit/audit.py":
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        if path.suffix.lower() not in {".md", ".mdx"}:
            for marker in PRIVATE_MARKERS:
                if marker.lower() in content.lower():
                    findings.append(f"private marker {marker!r}: {relative}")
        for marker in STALE_MARKERS:
            if marker.lower() in content.lower():
                findings.append(f"stale repository marker {marker!r}: {relative}")

        if relative.startswith(".github/workflows/"):
            if re.search(r"^\s*pull_request_target\s*:", content, re.M):
                findings.append(f"pull_request_target is prohibited: {relative}")
            if LARGER_RUNNER.search(content):
                findings.append(f"larger runner is prohibited: {relative}")
            if re.search(r"^\s*pull_request\s*:", content, re.M):
                if re.search(r"runs-on:[^\n]*self-hosted", content, re.I):
                    findings.append(f"fork workflow references self-hosted runner: {relative}")
                if "${{ secrets." in content:
                    findings.append(f"fork workflow references repository secrets: {relative}")

    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    findings = audit(args.repo_root.resolve())
    if findings:
        print("Open-source policy audit failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("Open-source policy audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
