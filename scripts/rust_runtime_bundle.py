from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tomllib
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BUNDLE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class BundleError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _relative(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise BundleError(f"{label} must be a string")
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"{label} must be repository-relative")
    return path.as_posix()


def load_bundle(path: pathlib.Path, bundle_id: str) -> dict[str, str]:
    if BUNDLE_ID.fullmatch(bundle_id) is None:
        raise BundleError("bundle id is invalid")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"bundle catalog is invalid JSON: {error}") from error
    if not isinstance(document, dict) or set(document) != {"schema", "bundles"}:
        raise BundleError("bundle catalog fields are invalid")
    if document.get("schema") != "elevenid.rust-cargo-runtime-bundles/v1":
        raise BundleError("bundle catalog schema is invalid")
    if not isinstance(document.get("bundles"), list):
        raise BundleError("bundles must be an array")
    matches = [
        item
        for item in document["bundles"]
        if isinstance(item, dict) and item.get("id") == bundle_id
    ]
    if len(matches) != 1:
        raise BundleError("bundle id is not uniquely activated")
    value = matches[0]
    expected = {
        "id",
        "repository",
        "revision",
        "manifest_path",
        "manifest_sha256",
        "lock_path",
        "lock_sha256",
        "subject_path",
        "subject_sha256",
    }
    if set(value) != expected:
        raise BundleError("bundle fields are invalid")
    repository = value.get("repository")
    revision = value.get("revision")
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        raise BundleError("bundle repository is invalid")
    if not isinstance(revision, str) or SHA.fullmatch(revision) is None:
        raise BundleError("bundle revision is invalid")
    manifest = _relative(value.get("manifest_path"), "manifest path")
    lock = _relative(value.get("lock_path"), "lock path")
    subject = _relative(value.get("subject_path"), "subject path")
    manifest_path = pathlib.PurePosixPath(manifest)
    if (
        not manifest.startswith(".github/feature-regression/")
        or manifest_path.name != "Cargo.toml"
        or pathlib.PurePosixPath(lock) != manifest_path.parent / "Cargo.lock"
        or pathlib.PurePosixPath(subject).parent != manifest_path.parent
    ):
        raise BundleError("bundle manifest, lock, and subject paths are invalid")
    for field in ("manifest_sha256", "lock_sha256", "subject_sha256"):
        if (
            not isinstance(value.get(field), str)
            or DIGEST.fullmatch(value[field]) is None
        ):
            raise BundleError(f"bundle {field} is invalid")
    return {key: str(value[key]) for key in sorted(expected)}


def verify_file(root: pathlib.Path, relative: str, expected: str) -> None:
    path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise BundleError(f"{relative} must be a regular non-symlink file")
    actual = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    if actual != expected:
        raise BundleError(f"{relative} digest does not match")


def verify_target(root: pathlib.Path, bundle: dict[str, str]) -> None:
    for name in ("manifest", "lock", "subject"):
        verify_file(root, bundle[f"{name}_path"], bundle[f"{name}_sha256"])
    manifest_path = root.joinpath(*pathlib.PurePosixPath(bundle["manifest_path"]).parts)
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"probe manifest is invalid TOML: {error}") from error
    binaries = manifest.get("bin")
    if (
        not isinstance(binaries, list)
        or len(binaries) != 1
        or not isinstance(binaries[0], dict)
        or binaries[0].get("name") != "elevenid-feature-regression-probe"
        or not isinstance(binaries[0].get("path"), str)
    ):
        raise BundleError("probe manifest must declare the one fixed probe binary")
    binary_path = pathlib.PurePosixPath(bundle["manifest_path"]).parent.joinpath(
        binaries[0]["path"]
    )
    if (
        any(part in {"", ".", ".."} for part in binary_path.parts)
        or binary_path.as_posix() != bundle["subject_path"]
    ):
        raise BundleError("probe manifest binary path must identify the subject")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_id")
    parser.add_argument("--catalog", type=pathlib.Path, required=True)
    parser.add_argument("--target", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        bundle = load_bundle(args.catalog, args.bundle_id)
        if args.target is not None:
            verify_target(args.target, bundle)
        sys.stdout.buffer.write(
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        )
        return 0
    except (OSError, BundleError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
