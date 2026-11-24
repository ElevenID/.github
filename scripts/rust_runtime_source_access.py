"""Protected-policy admission for code that can read a restricted Rust vendor image.

An image pull grant is insufficient: Cargo build scripts and proc macros can read
the vendor tree. Admit the entire immutable target revision and its locked Git
source closure before exposing that image to any candidate process.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import tomllib
import urllib.parse


CATALOG = pathlib.Path(__file__).parents[1] / "runtime/rust-cargo/source-access.json"
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
IMAGE = re.compile(
    r"ghcr\.io/elevenid/feature-regression-rust-cargo-restricted@sha256:[0-9a-f]{64}"
)
FIELDS = {
    "repository",
    "revision",
    "runtime_image",
    "runtime_manifest_sha256",
    "lock_sha256",
    "git_sources",
}


class SourceAccessError(ValueError):
    pass


def is_restricted_image(image: str) -> bool:
    return image.startswith(
        "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@"
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise SourceAccessError("source-access catalog contains duplicate fields")
        result[name] = value
    return result


def _identity(value: object) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"repository", "revision"}:
        raise SourceAccessError("source-access identity fields are invalid")
    repository, revision = value["repository"], value["revision"]
    if (
        not isinstance(repository, str)
        or REPOSITORY.fullmatch(repository) is None
        or not isinstance(revision, str)
        or SHA.fullmatch(revision) is None
    ):
        raise SourceAccessError(
            "source-access identity must be a repository and exact commit"
        )
    return repository.casefold(), revision


def locked_git_sources(lock: bytes) -> set[tuple[str, str]]:
    try:
        document = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SourceAccessError("source-access Cargo.lock is invalid") from error
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise SourceAccessError("source-access Cargo.lock has no packages")
    sources: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise SourceAccessError("source-access Cargo.lock package is invalid")
        source = package.get("source")
        if source is None:
            continue  # Local source is bound by the complete target revision.
        if not isinstance(source, str):
            raise SourceAccessError("source-access Cargo.lock source is invalid")
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            continue
        if not source.startswith("git+"):
            raise SourceAccessError("source-access Cargo.lock source is unsupported")
        url = urllib.parse.urlsplit(source[4:])
        repository = url.path.removeprefix("/").removesuffix(".git")
        if (
            url.scheme != "https"
            or url.netloc != "github.com"
            or REPOSITORY.fullmatch(repository) is None
            or SHA.fullmatch(url.fragment) is None
            or "%" in url.path
            or "\\" in source
        ):
            raise SourceAccessError(
                "source-access Git source must use exact HTTPS GitHub identity"
            )
        sources.add((repository.casefold(), url.fragment))
    return sources


def load_grants(path: pathlib.Path = CATALOG) -> list[dict[str, object]]:
    try:
        raw = path.read_bytes()
        if len(raw) > 1_048_576:
            raise SourceAccessError("source-access catalog exceeds its bound")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceAccessError("source-access catalog cannot be read") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "grants"}
        or document["schema"] != "elevenid.rust-runtime-source-access/v1"
        or not isinstance(document["grants"], list)
    ):
        raise SourceAccessError("source-access catalog fields are invalid")
    seen = set()
    for grant in document["grants"]:
        if not isinstance(grant, dict) or set(grant) != FIELDS:
            raise SourceAccessError("source-access grant fields are invalid")
        identity = _identity({key: grant[key] for key in ("repository", "revision")})
        if (
            not isinstance(grant["runtime_image"], str)
            or IMAGE.fullmatch(grant["runtime_image"]) is None
        ):
            raise SourceAccessError("source-access grant image is invalid")
        for name in ("runtime_manifest_sha256", "lock_sha256"):
            if (
                not isinstance(grant[name], str)
                or DIGEST.fullmatch(grant[name]) is None
            ):
                raise SourceAccessError("source-access grant digest is invalid")
        key = (*identity, grant["runtime_image"])
        if key in seen:
            raise SourceAccessError("source-access grant identity is duplicated")
        seen.add(key)
        if not isinstance(grant["git_sources"], list):
            raise SourceAccessError("source-access Git sources must be an array")
        sources = [_identity(value) for value in grant["git_sources"]]
        if len(set(sources)) != len(sources):
            raise SourceAccessError("source-access Git source is duplicated")
    return document["grants"]


def require_access(
    *,
    repository: str,
    revision: str,
    runtime_image: str,
    runtime_manifest_sha256: str,
    lock: bytes,
) -> None:
    identity = _identity({"repository": repository, "revision": revision})
    matches = [
        grant
        for grant in load_grants()
        if _identity({key: grant[key] for key in ("repository", "revision")})
        == identity
        and grant["runtime_image"] == runtime_image
    ]
    if len(matches) != 1:
        raise SourceAccessError(
            "restricted Rust source access is not admitted for this exact candidate"
        )
    grant = matches[0]
    if (
        grant["runtime_manifest_sha256"] != runtime_manifest_sha256
        or grant["lock_sha256"] != "sha256:" + hashlib.sha256(lock).hexdigest()
        or {_identity(value) for value in grant["git_sources"]}
        != locked_git_sources(lock)
    ):
        raise SourceAccessError(
            "restricted Rust source access differs from the admitted source closure"
        )
