"""Protected-policy admission for code that can read a restricted Rust vendor image.

An image pull grant is insufficient: Cargo build scripts and proc macros can read
the vendor tree. Admit the entire immutable target revision and its locked Git
source closure before exposing that image to any candidate process.
"""

from __future__ import annotations

import hashlib
import base64
import json
import pathlib
import re
import tomllib
import urllib.parse
import urllib.request


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
_REMOTE_CATALOGS: dict[str, tuple[bytes, list[dict[str, object]]]] = {}


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
    if len(lock) > 8_388_608:
        raise SourceAccessError("source-access Cargo.lock exceeds its bound")
    try:
        document = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SourceAccessError("source-access Cargo.lock is invalid") from error
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise SourceAccessError("source-access Cargo.lock has no packages")
    patch = document.get("patch", {})
    if not isinstance(patch, dict) or set(patch) - {"unused"}:
        raise SourceAccessError("source-access Cargo.lock patch fields are invalid")
    unused = patch.get("unused", [])
    if not isinstance(unused, list):
        raise SourceAccessError("source-access Cargo.lock unused patches are invalid")
    sources: set[tuple[str, str]] = set()
    # Include unused locked patches conservatively: source access must not be
    # inferred from whether a given Cargo invocation happens to select a crate.
    for package in [*packages, *unused]:
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
    except OSError as error:
        raise SourceAccessError("source-access catalog cannot be read") from error
    return parse_grants(raw)


def parse_grants(raw: bytes) -> list[dict[str, object]]:
    try:
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
    grants: list[dict[str, object]] | None = None,
) -> str:
    identity = _identity({"repository": repository, "revision": revision})
    matches = [
        grant
        for grant in (load_grants() if grants is None else grants)
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
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(grant, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _policy_api(path: str, token: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ElevenID-source-access",
        "Cache-Control": "no-cache",
    }
    if token:
        if re.fullmatch(r"[A-Za-z0-9_.\-]{8,512}", token) is None:
            raise SourceAccessError("source-access API credential is invalid")
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        "https://api.github.com/repos/ElevenID/.github/" + path, headers=headers
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(
            request, timeout=30
        ) as response:
            raw = response.read(2_097_153)
            if response.status != 200 or len(raw) > 2_097_152:
                raise SourceAccessError("protected source-access policy is unavailable")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise SourceAccessError(
            "protected source-access policy is unavailable"
        ) from error
    if not isinstance(value, dict):
        raise SourceAccessError("protected source-access API object is invalid")
    return value


def _main_revision(token: str) -> str:
    value = _policy_api("git/ref/heads/main", token)
    obj = value.get("object")
    if (
        value.get("ref") != "refs/heads/main"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
        or not isinstance(obj.get("sha"), str)
        or SHA.fullmatch(obj["sha"]) is None
    ):
        raise SourceAccessError("protected source-access main identity is invalid")
    return obj["sha"]


def _remote_catalog(revision: str, token: str) -> tuple[bytes, list[dict[str, object]]]:
    if SHA.fullmatch(revision) is None:
        raise SourceAccessError("source-access policy revision is invalid")
    if revision in _REMOTE_CATALOGS:
        return _REMOTE_CATALOGS[revision]
    value = _policy_api(
        "contents/runtime/rust-cargo/source-access.json?ref=" + revision, token
    )
    if (
        value.get("type") != "file"
        or value.get("path") != "runtime/rust-cargo/source-access.json"
        or value.get("encoding") != "base64"
        or not isinstance(value.get("content"), str)
    ):
        raise SourceAccessError("protected source-access catalog metadata is invalid")
    try:
        raw = base64.b64decode("".join(value["content"].splitlines()), validate=True)
    except ValueError as error:
        raise SourceAccessError(
            "protected source-access catalog encoding is invalid"
        ) from error
    if (
        len(raw) != value.get("size")
        or len(raw) > 1_048_576
        or hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
        ).hexdigest()
        != value.get("sha")
    ):
        raise SourceAccessError("protected source-access catalog bytes differ")
    result = raw, parse_grants(raw)
    # Cache only immutable public data, never credentials or the main pointer.
    if len(_REMOTE_CATALOGS) >= 128:
        _REMOTE_CATALOGS.pop(next(iter(_REMOTE_CATALOGS)))
    _REMOTE_CATALOGS[revision] = result
    return result


def admit_from_protected_main(*, token: str, **candidate) -> dict[str, str]:
    revision = _main_revision(token)
    raw, grants = _remote_catalog(revision, token)
    grant = require_access(**candidate, grants=grants)
    return {
        "policy_repository": "ElevenID/.github",
        "policy_revision": revision,
        "catalog_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "grant_sha256": grant,
    }


def verify_protected_admission(proof: object, *, token: str, **candidate) -> None:
    fields = {"policy_repository", "policy_revision", "catalog_sha256", "grant_sha256"}
    if (
        not isinstance(proof, dict)
        or set(proof) != fields
        or proof.get("policy_repository") != "ElevenID/.github"
        or not all(isinstance(proof.get(name), str) for name in fields)
        or SHA.fullmatch(proof["policy_revision"]) is None
        or any(
            DIGEST.fullmatch(proof[name]) is None
            for name in ("catalog_sha256", "grant_sha256")
        )
    ):
        raise SourceAccessError("source-access receipt identity is invalid")
    raw, grants = _remote_catalog(proof["policy_revision"], token)
    if (
        "sha256:" + hashlib.sha256(raw).hexdigest() != proof["catalog_sha256"]
        or require_access(**candidate, grants=grants) != proof["grant_sha256"]
    ):
        raise SourceAccessError(
            "source-access receipt does not match its immutable policy"
        )
    current = _main_revision(token)
    if current != proof["policy_revision"]:
        comparison = _policy_api(
            "compare/" + proof["policy_revision"] + "..." + current, token
        )
        if comparison.get("status") not in {"ahead", "identical"}:
            raise SourceAccessError(
                "source-access policy was not integrated into protected main"
            )
    _, current_grants = _remote_catalog(current, token)
    # Revocation applies even to a previously valid historical receipt.
    require_access(**candidate, grants=current_grants)
