"""Preview or remove expired, disposable Marty workspace evidence."""

import argparse
import json
import os
import shutil
import stat
import time
from pathlib import Path

CONTAINERS = {
    "artifacts": 30,
    "_codex-artifacts": 30,
    "_codex-diagnostics": 14,
    "_codex-ci-diagnostics": 14,
    ".codex-validation": 14,
    "_codex-validation": 14,
    "test-temp": 14,
}
PRESERVE = (
    "backup",
    "archive",
    "predeletion",
    "recovery",
    "selfhost",
    "runtime",
    "installed",
    "baseline",
    "attest",
    "manifest",
    "release",
    "rollback",
    "snapshot",
)


def linked(path):
    """Reject symlinks, junctions, and other Windows reparse points."""
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def protected(path):
    return any(word in path.name.lower() for word in PRESERVE)


def validate_target(root, path):
    """Require a direct child of a named scratch container inside the workspace."""
    if path.parent.parent != root or path.parent.name not in CONTAINERS:
        raise ValueError(f"Not a named workspace output child: {path}")
    if linked(path.parent) or linked(path):
        raise ValueError(f"Refusing linked workspace output: {path}")
    resolved = path.resolve(strict=True)
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError(f"Path escapes workspace: {path}")


def inspect(path):
    """Return newest modification and size; protected trees are never candidates."""
    if linked(path) or protected(path):
        return None
    newest = path.stat().st_mtime
    size = 0

    def fail(error):
        raise error

    for base, dirs, files in os.walk(path, onerror=fail) if path.is_dir() else []:
        if (Path(base) / ".git").exists():
            return None
        for name in dirs + files:
            child = Path(base) / name
            if linked(child) or protected(child):
                return None
            info = child.stat()
            newest = max(newest, info.st_mtime)
            if child.is_file():
                size += info.st_size
    if path.is_file():
        size = path.stat().st_size
    return newest, size


def candidates(root, now):
    for name, days in CONTAINERS.items():
        container = root / name
        if not container.is_dir() or linked(container) or (container / ".git").exists():
            continue
        for path in sorted(container.iterdir()):
            if linked(path) or protected(path):
                continue
            # Fixed containers and direct children only; never traverse a repository.
            validate_target(root, path)
            result = inspect(path)
            if result is not None and result[0] < now - days * 86400:
                yield path, days, result[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument(
        "--apply", action="store_true", help="Delete listed expired output"
    )
    args = parser.parse_args()
    root = args.workspace.resolve(strict=True)
    if not root.is_dir() or (root / ".git").exists():
        parser.error(
            "workspace must be an existing multi-repository workspace, not a Git checkout"
        )
    count = size = 0
    for path, days, byte_count in candidates(root, time.time()):
        if args.apply:
            # Reinspect immediately before deletion; newly written output is preserved.
            if linked(path.parent) or linked(path):
                continue
            validate_target(root, path)
            result = inspect(path)
            if result is None or result[0] >= time.time() - days * 86400:
                continue
            # Windows recursive deletion is bounded again immediately before use.
            validate_target(root, path)
            byte_count = result[1]
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        print(
            json.dumps(
                {
                    "path": str(path.relative_to(root)),
                    "retention_days": days,
                    "bytes": byte_count,
                    "action": "deleted" if args.apply else "would_delete",
                }
            )
        )
        count += 1
        size += byte_count
    print(json.dumps({"entries": count, "bytes": size, "applied": args.apply}))


if __name__ == "__main__":
    main()
