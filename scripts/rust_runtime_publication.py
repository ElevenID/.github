from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections.abc import Mapping
from typing import Any

from scripts.rust_runtime_bundle import BundleError, load_bundle


BUILDX_VERSION = "v0.37.1"
BUILDX_LINUX_AMD64_SHA256 = (
    "sha256:9447199cdb435f25880548343c128a4b6650e8891ee598905d8d29d39a8e359b"
)
BUILDX_ASSET = "buildx-v0.37.1.linux-amd64"
BUILDKIT_VERSION = "v0.33.0"
BUILDKIT_IMAGE = (
    "moby/buildkit:v0.33.0@sha256:"
    "6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3"
)
SBOM_GENERATOR = (
    "docker/buildkit-syft-scanner:stable-1@sha256:"
    "ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9"
)
SBOM_GENERATOR_PROVENANCE_URI = (
    "pkg:docker/docker/buildkit-syft-scanner@1.12.0?platform=linux%2Famd64"
)
SBOM_GENERATOR_LINUX_AMD64_DIGEST = (
    "sha256:187e1892a7752c9384c59aba9517dd8e40610b748c72773e87b63720514463c2"
)
RUST_BASE_IMAGE = (
    "rust:1.95-bookworm@sha256:"
    "6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
)
RUST_BASE_LINUX_AMD64_DIGEST = (
    "sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb"
)
RUST_BASE_PROVENANCE_URI = "pkg:docker/rust@1.95-bookworm?platform=linux%2Famd64"
PYTHON_BASE_IMAGE = (
    "python:3.11.16-bookworm@sha256:"
    "b99029c95d3d37fb1e4e76d287f7984373dca77c665885986e31b2c95260c13c"
)
PYTHON_BASE_LINUX_AMD64_DIGEST = (
    "sha256:00f0ecbf74ff8f915020d5a40c4bc6a83f46cd7b83f47db51c7e204f0d8a3ec2"
)
PYTHON_BASE_PROVENANCE_URI = "pkg:docker/python@3.11.16-bookworm?platform=linux%2Famd64"
IMAGE_REPOSITORY = "ghcr.io/elevenid/feature-regression-rust-cargo"
WRAPPER_PATH = (
    pathlib.Path(__file__).parents[1] / "runtime" / "rust-cargo" / "run-rust-probe"
)
BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class PublicationError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise PublicationError(f"duplicate JSON key {key!r}")
        value[key] = child
    return value


def _json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PublicationError(f"{label} contains non-finite value {value}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"{label} is invalid JSON: {error}") from error


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicationError(f"{label} must be an object")
    return value


def _digest(path: pathlib.Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _attestation_payload(
    value: Mapping[str, Any], field: str, label: str
) -> Mapping[str, Any]:
    direct = value.get(field)
    if isinstance(direct, Mapping):
        return direct
    platform_values = [
        item[field]
        for item in value.values()
        if isinstance(item, Mapping) and isinstance(item.get(field), Mapping)
    ]
    if len(platform_values) != 1:
        raise PublicationError(f"{label} must contain one platform's {field} evidence")
    return platform_values[0]


def _expected_labels(bundle: Mapping[str, str]) -> dict[str, str]:
    prefix = "io.elevenid.feature-regression.probe."
    return {
        "org.opencontainers.image.source": "https://github.com/ElevenID/.github",
        f"{prefix}repository": bundle["repository"],
        f"{prefix}revision": bundle["revision"],
        f"{prefix}manifest": bundle["manifest_path"],
        f"{prefix}manifest-sha256": bundle["manifest_sha256"],
        f"{prefix}lock": bundle["lock_path"],
        f"{prefix}lock-sha256": bundle["lock_sha256"],
        f"{prefix}subject": bundle["subject_path"],
        f"{prefix}subject-sha256": bundle["subject_sha256"],
        f"{prefix}builder.buildx-version": BUILDX_VERSION,
        f"{prefix}builder.buildx-sha256": BUILDX_LINUX_AMD64_SHA256,
        f"{prefix}builder.buildkit-image": BUILDKIT_IMAGE,
        f"{prefix}builder.sbom-generator": SBOM_GENERATOR,
        f"{prefix}builder.sbom-generator-linux-amd64-digest": (
            SBOM_GENERATOR_LINUX_AMD64_DIGEST
        ),
        f"{prefix}runtime.python-base-image": PYTHON_BASE_IMAGE,
        f"{prefix}runtime.python-base-linux-amd64-digest": (
            PYTHON_BASE_LINUX_AMD64_DIGEST
        ),
    }


def _expected_build_arguments(bundle: Mapping[str, str]) -> dict[str, str]:
    return {
        "BUILDX_VERSION": BUILDX_VERSION,
        "BUILDX_SHA256": BUILDX_LINUX_AMD64_SHA256,
        "BUILDKIT_IMAGE": BUILDKIT_IMAGE,
        "SBOM_GENERATOR": SBOM_GENERATOR,
        "SBOM_GENERATOR_LINUX_AMD64_DIGEST": (SBOM_GENERATOR_LINUX_AMD64_DIGEST),
        "PYTHON_BASE_IMAGE": PYTHON_BASE_IMAGE,
        "PYTHON_BASE_LINUX_AMD64_DIGEST": PYTHON_BASE_LINUX_AMD64_DIGEST,
        "PROBE_REPOSITORY": bundle["repository"],
        "PROBE_REVISION": bundle["revision"],
        "PROBE_MANIFEST_PATH": bundle["manifest_path"],
        "PROBE_MANIFEST_SHA256": bundle["manifest_sha256"],
        "PROBE_LOCK_PATH": bundle["lock_path"],
        "PROBE_LOCK_SHA256": bundle["lock_sha256"],
        "PROBE_SUBJECT_PATH": bundle["subject_path"],
        "PROBE_SUBJECT_SHA256": bundle["subject_sha256"],
    }


def _validate_linux_amd64_index(
    value: Mapping[str, Any], label: str, image: str, platform_digest: str
) -> None:
    manifests = value.get("manifests")
    if (
        value.get("digest") != image.rsplit("@", 1)[1]
        or not isinstance(manifests, list)
        or not any(
            isinstance(item, Mapping)
            and item.get("digest") == platform_digest
            and item.get("platform") == {"architecture": "amd64", "os": "linux"}
            for item in manifests
        )
    ):
        raise PublicationError(f"{label} linux/amd64 image does not match")


def validate_publication_evidence(
    evidence_dir: pathlib.Path,
    bundle: Mapping[str, str],
    *,
    image: str,
    publisher_revision: str,
) -> dict[str, Any]:
    image_prefix = f"{IMAGE_REPOSITORY}@"
    if (
        not image.startswith(image_prefix)
        or DIGEST.fullmatch(image.removeprefix(image_prefix)) is None
    ):
        raise PublicationError("published image reference is invalid")
    if SHA.fullmatch(publisher_revision) is None:
        raise PublicationError("publisher revision is invalid")

    required = {
        "build-metadata.json",
        "buildkit-container.json",
        "buildkit-image.json",
        "buildx-version.txt",
        "buildx-identity.json",
        "buildkit-inspect.txt",
        "image-index.json",
        "labels.json",
        "provenance.json",
        "python-base-index.json",
        "runtime-manifest.json",
        "rust-base-index.json",
        "sbom-generator-index.json",
        "sbom.json",
    }
    entries = list(evidence_dir.iterdir())
    if {path.name for path in entries} != required or any(
        path.is_symlink() or not path.is_file() for path in entries
    ):
        raise PublicationError("publication evidence files do not match the schema")

    buildx_version = (evidence_dir / "buildx-version.txt").read_text(encoding="utf-8")
    if (
        re.search(rf"(?<![0-9.]){re.escape(BUILDX_VERSION)}(?![0-9.])", buildx_version)
        is None
    ):
        raise PublicationError("Buildx version evidence does not match")
    buildx_identity = _mapping(
        _json(evidence_dir / "buildx-identity.json", "Buildx identity"),
        "Buildx identity",
    )
    if dict(buildx_identity) != {
        "asset": BUILDX_ASSET,
        "platform": "linux/amd64",
        "sha256": BUILDX_LINUX_AMD64_SHA256,
        "version": BUILDX_VERSION,
    }:
        raise PublicationError("Buildx executable identity does not match")
    buildkit_inspect = (evidence_dir / "buildkit-inspect.txt").read_text(
        encoding="utf-8"
    )
    if (
        re.search(
            rf"(?<![0-9.]){re.escape(BUILDKIT_VERSION)}(?![0-9.])",
            buildkit_inspect,
        )
        is None
    ):
        raise PublicationError("BuildKit version evidence does not match")
    buildkit_container = _mapping(
        _json(evidence_dir / "buildkit-container.json", "BuildKit container"),
        "BuildKit container",
    )
    buildkit_image = _mapping(
        _json(evidence_dir / "buildkit-image.json", "BuildKit image"),
        "BuildKit image",
    )
    buildkit_image_id = buildkit_container.get("image_id")
    if (
        buildkit_container.get("configured_image") != BUILDKIT_IMAGE
        or not isinstance(buildkit_image_id, str)
        or DIGEST.fullmatch(buildkit_image_id) is None
        or buildkit_image.get("image_id") != buildkit_image_id
    ):
        raise PublicationError("BuildKit container image evidence does not match")
    repo_digests = buildkit_image.get("repo_digests")
    expected_buildkit_digest = BUILDKIT_IMAGE.rsplit("@", 1)[1]
    if not isinstance(repo_digests, list) or not any(
        value
        in {
            f"moby/buildkit@{expected_buildkit_digest}",
            f"docker.io/moby/buildkit@{expected_buildkit_digest}",
        }
        for value in repo_digests
    ):
        raise PublicationError("BuildKit local image digest does not match")

    scanner_index = _mapping(
        _json(evidence_dir / "sbom-generator-index.json", "SBOM generator index"),
        "SBOM generator index",
    )
    _validate_linux_amd64_index(
        scanner_index,
        "SBOM generator",
        SBOM_GENERATOR,
        SBOM_GENERATOR_LINUX_AMD64_DIGEST,
    )
    rust_index = _mapping(
        _json(evidence_dir / "rust-base-index.json", "Rust base index"),
        "Rust base index",
    )
    _validate_linux_amd64_index(
        rust_index,
        "Rust base",
        RUST_BASE_IMAGE,
        RUST_BASE_LINUX_AMD64_DIGEST,
    )
    python_index = _mapping(
        _json(evidence_dir / "python-base-index.json", "Python base index"),
        "Python base index",
    )
    _validate_linux_amd64_index(
        python_index,
        "Python base",
        PYTHON_BASE_IMAGE,
        PYTHON_BASE_LINUX_AMD64_DIGEST,
    )

    metadata = _mapping(
        _json(evidence_dir / "build-metadata.json", "build metadata"),
        "build metadata",
    )
    expected_digest = image.rsplit("@", 1)[1]
    if metadata.get("containerimage.digest") != expected_digest:
        raise PublicationError("build metadata image digest does not match")

    image_index = _mapping(
        _json(evidence_dir / "image-index.json", "OCI image index"),
        "OCI image index",
    )
    manifests = image_index.get("manifests")
    if not isinstance(manifests, list) or not any(
        isinstance(item, Mapping)
        and isinstance(item.get("annotations"), Mapping)
        and item["annotations"].get("vnd.docker.reference.type")
        == "attestation-manifest"
        for item in manifests
    ):
        raise PublicationError("OCI image index has no attestation manifest")

    provenance = _mapping(
        _json(evidence_dir / "provenance.json", "provenance"), "provenance"
    )
    slsa = _attestation_payload(provenance, "SLSA", "provenance")
    definition = _mapping(slsa.get("buildDefinition"), "provenance build definition")
    if definition.get("buildType") != BUILD_TYPE:
        raise PublicationError("provenance build type does not match")
    external = _mapping(
        definition.get("externalParameters"), "provenance external parameters"
    )
    request = _mapping(external.get("request"), "provenance request")
    if request.get("frontend") != "dockerfile.v0":
        raise PublicationError("provenance frontend does not match")
    arguments = _mapping(request.get("args"), "provenance build arguments")
    for name, expected in _expected_build_arguments(bundle).items():
        if arguments.get(f"build-arg:{name}") != expected:
            raise PublicationError(f"provenance build argument {name} does not match")
    materials = definition.get("resolvedDependencies")
    if not isinstance(materials, list) or not materials:
        raise PublicationError("provenance materials are missing")
    scanner_material = False
    rust_material = False
    python_material = False
    for material in materials:
        item = _mapping(material, "provenance material")
        uri = item.get("uri")
        digests = _mapping(item.get("digest"), "provenance material digest")
        if not isinstance(uri, str) or not uri:
            raise PublicationError("provenance material URI is invalid")
        if not any(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in digests.values()
        ):
            raise PublicationError("provenance material digest is invalid")
        scanner_material = scanner_material or (
            uri == SBOM_GENERATOR_PROVENANCE_URI
            and dict(digests)
            == {
                "sha256": SBOM_GENERATOR.rsplit("@sha256:", 1)[1],
            }
        )
        rust_material = rust_material or (
            uri == RUST_BASE_PROVENANCE_URI
            and dict(digests) == {"sha256": RUST_BASE_IMAGE.rsplit("@sha256:", 1)[1]}
        )
        python_material = python_material or (
            uri == PYTHON_BASE_PROVENANCE_URI
            and dict(digests) == {"sha256": PYTHON_BASE_IMAGE.rsplit("@sha256:", 1)[1]}
        )
    if not scanner_material:
        raise PublicationError(
            "provenance does not identify the exact SBOM generator material"
        )
    if not rust_material:
        raise PublicationError(
            "provenance does not identify the exact Rust base image material"
        )
    if not python_material:
        raise PublicationError(
            "provenance does not identify the exact Python base image material"
        )

    sbom = _mapping(_json(evidence_dir / "sbom.json", "SBOM"), "SBOM")
    spdx = _attestation_payload(sbom, "SPDX", "SBOM")
    if (
        spdx.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not str(spdx.get("spdxVersion", "")).startswith("SPDX-2.")
        or not isinstance(spdx.get("packages"), list)
        or not spdx["packages"]
    ):
        raise PublicationError("SPDX SBOM fields are invalid")

    labels = _mapping(_json(evidence_dir / "labels.json", "OCI labels"), "OCI labels")
    for name, expected in _expected_labels(bundle).items():
        if labels.get(name) != expected:
            raise PublicationError(f"OCI label {name} does not match")

    runtime_path = evidence_dir / "runtime-manifest.json"
    runtime_document = _mapping(
        _json(runtime_path, "runtime manifest"), "runtime manifest"
    )
    runtime_fields = {
        "cargo_version",
        "profile",
        "python_version",
        "rustc_version",
        "schema",
        "vendor_lock_sha256",
        "wrapper_sha256",
    }
    if (
        set(runtime_document) != runtime_fields
        or runtime_document.get("schema") != "elevenid.rust-cargo-runtime/v1"
        or runtime_document.get("profile") != "rust-cargo-v1"
        or runtime_document.get("vendor_lock_sha256") != bundle["lock_sha256"]
        or runtime_document.get("wrapper_sha256") != _digest(WRAPPER_PATH)
        or any(
            not isinstance(runtime_document.get(field), str)
            or not runtime_document[field]
            or "\x00" in runtime_document[field]
            for field in ("cargo_version", "python_version", "rustc_version")
        )
    ):
        raise PublicationError("runtime manifest fields do not match")
    canonical_runtime = json.dumps(
        runtime_document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if runtime_path.read_bytes() != canonical_runtime:
        raise PublicationError("runtime manifest is not canonical JSON")

    return {
        "build_metadata_sha256": _digest(evidence_dir / "build-metadata.json"),
        "buildkit_container_sha256": _digest(evidence_dir / "buildkit-container.json"),
        "buildkit_image_evidence_sha256": _digest(evidence_dir / "buildkit-image.json"),
        "buildkit_inspect_sha256": _digest(evidence_dir / "buildkit-inspect.txt"),
        "buildkit_image": BUILDKIT_IMAGE,
        "buildkit_version": BUILDKIT_VERSION,
        "buildx_asset": BUILDX_ASSET,
        "buildx_identity_sha256": _digest(evidence_dir / "buildx-identity.json"),
        "buildx_linux_amd64_sha256": BUILDX_LINUX_AMD64_SHA256,
        "buildx_version_evidence_sha256": _digest(evidence_dir / "buildx-version.txt"),
        "buildx_version": BUILDX_VERSION,
        "bundle": dict(bundle),
        "image": image,
        "image_index_sha256": _digest(evidence_dir / "image-index.json"),
        "labels_sha256": _digest(evidence_dir / "labels.json"),
        "provenance_sha256": _digest(evidence_dir / "provenance.json"),
        "publisher_revision": publisher_revision,
        "python_base_image": PYTHON_BASE_IMAGE,
        "python_base_index_sha256": _digest(evidence_dir / "python-base-index.json"),
        "python_base_linux_amd64_digest": PYTHON_BASE_LINUX_AMD64_DIGEST,
        "runtime_manifest": dict(runtime_document),
        "runtime_manifest_sha256": _digest(runtime_path),
        "rust_base_image": RUST_BASE_IMAGE,
        "rust_base_index_sha256": _digest(evidence_dir / "rust-base-index.json"),
        "rust_base_linux_amd64_digest": RUST_BASE_LINUX_AMD64_DIGEST,
        "sbom_generator": SBOM_GENERATOR,
        "sbom_generator_index_sha256": _digest(
            evidence_dir / "sbom-generator-index.json"
        ),
        "sbom_generator_linux_amd64_digest": (SBOM_GENERATOR_LINUX_AMD64_DIGEST),
        "sbom_sha256": _digest(evidence_dir / "sbom.json"),
        "schema": "elevenid.rust-cargo-publication/v1",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=pathlib.Path, required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--publisher-revision", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = load_bundle(args.catalog, args.bundle_id)
        document = validate_publication_evidence(
            args.evidence_dir,
            bundle,
            image=args.image,
            publisher_revision=args.publisher_revision,
        )
        args.output.write_bytes(
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        return 0
    except (OSError, BundleError, PublicationError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
