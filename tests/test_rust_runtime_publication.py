from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import yaml

from scripts import rust_runtime_publication as publication


IMAGE_DIGEST = "sha256:" + "9" * 64
IMAGE = f"{publication.IMAGE_REPOSITORY}@{IMAGE_DIGEST}"
PUBLISHER_REVISION = "e" * 40
BUNDLE = {
    "id": "marty-ui",
    "repository": "ElevenID/marty-ui",
    "revision": "a" * 40,
    "manifest_path": ".github/feature-regression/rust-probe/Cargo.toml",
    "manifest_sha256": "sha256:" + "b" * 64,
    "lock_path": ".github/feature-regression/rust-probe/Cargo.lock",
    "lock_sha256": "sha256:" + "c" * 64,
    "subject_path": ".github/feature-regression/rust-probe/behavior_subject.rs",
    "subject_sha256": "sha256:" + "d" * 64,
}
PINNED_BUILDERS = {
    "buildx_version": "v0.37.1",
    "buildx_linux_amd64_sha256": (
        "sha256:9447199cdb435f25880548343c128a4b6650e8891ee598905d8d29d39a8e359b"
    ),
    "buildkit_version": "v0.33.0",
    "buildkit_image": (
        "moby/buildkit:v0.33.0@sha256:"
        "6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3"
    ),
    "sbom_generator": (
        "docker/buildkit-syft-scanner:stable-1@sha256:"
        "ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9"
    ),
}


def write_json(path: pathlib.Path, value: object, *, canonical: bool = False) -> None:
    options: dict[str, object] = {}
    if canonical:
        options = {"ensure_ascii": False, "sort_keys": True, "separators": (",", ":")}
    path.write_text(json.dumps(value, **options), encoding="utf-8")


def platform_index_document(image: str, platform_digest: str) -> dict[str, object]:
    return {
        "digest": image.rsplit("@", 1)[1],
        "manifests": [
            {
                "digest": platform_digest,
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "schemaVersion": 2,
    }


def provenance_document(
    *,
    include_scanner: bool = True,
    scanner_uri: str | None = None,
    scanner_digest: str | None = None,
) -> dict[str, object]:
    materials = [
        {
            "uri": publication.RUST_BASE_PROVENANCE_URI,
            "digest": {"sha256": publication.RUST_BASE_IMAGE.rsplit("@sha256:", 1)[1]},
        },
        {
            "uri": publication.PYTHON_BASE_PROVENANCE_URI,
            "digest": {
                "sha256": publication.PYTHON_BASE_IMAGE.rsplit("@sha256:", 1)[1]
            },
        },
    ]
    if include_scanner:
        materials.insert(
            0,
            {
                "uri": scanner_uri or publication.SBOM_GENERATOR_PROVENANCE_URI,
                "digest": {
                    "sha256": scanner_digest
                    or publication.SBOM_GENERATOR.rsplit("@sha256:", 1)[1]
                },
            },
        )
    arguments = {
        f"build-arg:{name}": value
        for name, value in publication._expected_build_arguments(BUNDLE).items()
    }
    return {
        "SLSA": {
            "buildDefinition": {
                "buildType": publication.BUILD_TYPE,
                "externalParameters": {
                    "request": {"args": arguments, "frontend": "dockerfile.v0"}
                },
                "resolvedDependencies": materials,
            },
            "runDetails": {"builder": {"id": ""}},
        }
    }


class RustRuntimePublicationTests(unittest.TestCase):
    def evidence(self, root: pathlib.Path) -> pathlib.Path:
        write_json(
            root / "build-metadata.json", {"containerimage.digest": IMAGE_DIGEST}
        )
        buildkit_image_id = "sha256:" + "4" * 64
        write_json(
            root / "buildkit-container.json",
            {
                "configured_image": publication.BUILDKIT_IMAGE,
                "image_id": buildkit_image_id,
            },
        )
        write_json(
            root / "buildkit-image.json",
            {
                "image_id": buildkit_image_id,
                "repo_digests": [
                    "moby/buildkit@" + publication.BUILDKIT_IMAGE.rsplit("@", 1)[1]
                ],
            },
        )
        (root / "buildx-version.txt").write_text(
            f"github.com/docker/buildx {publication.BUILDX_VERSION} official\n",
            encoding="utf-8",
        )
        write_json(
            root / "buildx-identity.json",
            {
                "asset": publication.BUILDX_ASSET,
                "platform": "linux/amd64",
                "sha256": publication.BUILDX_LINUX_AMD64_SHA256,
                "version": publication.BUILDX_VERSION,
            },
            canonical=True,
        )
        (root / "buildkit-inspect.txt").write_text(
            f"BuildKit version: {publication.BUILDKIT_VERSION}\n",
            encoding="utf-8",
        )
        write_json(
            root / "image-index.json",
            {
                "schemaVersion": 2,
                "manifests": [
                    {"platform": {"architecture": "amd64", "os": "linux"}},
                    {
                        "annotations": {
                            "vnd.docker.reference.type": "attestation-manifest"
                        },
                        "platform": {"architecture": "unknown", "os": "unknown"},
                    },
                ],
            },
        )
        write_json(root / "labels.json", publication._expected_labels(BUNDLE))
        write_json(root / "provenance.json", provenance_document())
        write_json(
            root / "sbom-generator-index.json",
            platform_index_document(
                publication.SBOM_GENERATOR,
                publication.SBOM_GENERATOR_LINUX_AMD64_DIGEST,
            ),
        )
        write_json(
            root / "rust-base-index.json",
            platform_index_document(
                publication.RUST_BASE_IMAGE,
                publication.RUST_BASE_LINUX_AMD64_DIGEST,
            ),
        )
        write_json(
            root / "python-base-index.json",
            platform_index_document(
                publication.PYTHON_BASE_IMAGE,
                publication.PYTHON_BASE_LINUX_AMD64_DIGEST,
            ),
        )
        write_json(
            root / "sbom.json",
            {
                "SPDX": {
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "spdxVersion": "SPDX-2.3",
                    "packages": [{"name": "cargo", "versionInfo": "1.95.0"}],
                }
            },
        )
        write_json(
            root / "runtime-manifest.json",
            {
                "cargo_version": "cargo 1.95.0",
                "profile": "rust-cargo-v1",
                "python_version": "Python 3.11.2",
                "rustc_version": "rustc 1.95.0",
                "schema": "elevenid.rust-cargo-runtime/v1",
                "vendor_lock_sha256": BUNDLE["lock_sha256"],
                "wrapper_sha256": publication._digest(publication.WRAPPER_PATH),
            },
            canonical=True,
        )
        return root

    def validate(self, root: pathlib.Path) -> dict[str, object]:
        return publication.validate_publication_evidence(
            root,
            BUNDLE,
            image=IMAGE,
            publisher_revision=PUBLISHER_REVISION,
        )

    def test_structured_evidence_binds_builder_sbom_labels_and_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = self.validate(self.evidence(pathlib.Path(temporary)))
        self.assertEqual(publication.BUILDX_VERSION, document["buildx_version"])
        self.assertEqual(
            publication.BUILDX_LINUX_AMD64_SHA256,
            document["buildx_linux_amd64_sha256"],
        )
        self.assertEqual(publication.BUILDKIT_VERSION, document["buildkit_version"])
        self.assertEqual(publication.BUILDKIT_IMAGE, document["buildkit_image"])
        self.assertEqual(publication.SBOM_GENERATOR, document["sbom_generator"])
        self.assertEqual(
            publication.SBOM_GENERATOR_LINUX_AMD64_DIGEST,
            document["sbom_generator_linux_amd64_digest"],
        )
        self.assertEqual(publication.RUST_BASE_IMAGE, document["rust_base_image"])
        self.assertEqual(
            publication.RUST_BASE_LINUX_AMD64_DIGEST,
            document["rust_base_linux_amd64_digest"],
        )
        self.assertEqual(publication.PYTHON_BASE_IMAGE, document["python_base_image"])
        self.assertEqual(
            publication.PYTHON_BASE_LINUX_AMD64_DIGEST,
            document["python_base_linux_amd64_digest"],
        )
        self.assertEqual(BUNDLE, document["bundle"])
        self.assertEqual(IMAGE, document["image"])

    def test_current_platform_wrapped_attestation_shape_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.evidence(pathlib.Path(temporary))
            provenance = json.loads(
                (root / "provenance.json").read_text(encoding="utf-8")
            )
            sbom = json.loads((root / "sbom.json").read_text(encoding="utf-8"))
            write_json(root / "provenance.json", {"linux/amd64": provenance})
            write_json(root / "sbom.json", {"linux/amd64": sbom})
            document = self.validate(root)
        self.assertEqual(publication.BUILDKIT_IMAGE, document["buildkit_image"])

    def test_workflow_module_cli_emits_canonical_validated_publication(self) -> None:
        repository_root = pathlib.Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            self.evidence(evidence)
            catalog = root / "bundles.json"
            write_json(
                catalog,
                {
                    "bundles": [BUNDLE],
                    "schema": "elevenid.rust-cargo-runtime-bundles/v1",
                },
                canonical=True,
            )
            output = evidence / "publication.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "scripts.rust_runtime_publication",
                    "--catalog",
                    str(catalog),
                    "--bundle-id",
                    "marty-ui",
                    "--evidence-dir",
                    str(evidence),
                    "--image",
                    IMAGE,
                    "--publisher-revision",
                    PUBLISHER_REVISION,
                    "--output",
                    str(output),
                ],
                cwd=repository_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr.decode())
            document = json.loads(output.read_bytes())
            self.assertEqual(
                {
                    "build_metadata_sha256",
                    "buildkit_container_sha256",
                    "buildkit_image",
                    "buildkit_image_evidence_sha256",
                    "buildkit_inspect_sha256",
                    "buildkit_version",
                    "buildx_asset",
                    "buildx_identity_sha256",
                    "buildx_linux_amd64_sha256",
                    "buildx_version",
                    "buildx_version_evidence_sha256",
                    "bundle",
                    "image",
                    "image_index_sha256",
                    "labels_sha256",
                    "provenance_sha256",
                    "publisher_revision",
                    "python_base_image",
                    "python_base_index_sha256",
                    "python_base_linux_amd64_digest",
                    "runtime_manifest",
                    "runtime_manifest_sha256",
                    "rust_base_image",
                    "rust_base_index_sha256",
                    "rust_base_linux_amd64_digest",
                    "sbom_generator",
                    "sbom_generator_index_sha256",
                    "sbom_generator_linux_amd64_digest",
                    "sbom_sha256",
                    "schema",
                },
                set(document),
            )
            self.assertEqual(
                output.read_bytes(),
                json.dumps(
                    document,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode(),
            )

    def test_structured_evidence_rejects_tampering(self) -> None:
        mutations = {
            "metadata digest": (
                "build-metadata.json",
                {"containerimage.digest": "sha256:" + "0" * 64},
                "image digest",
            ),
            "missing scanner material": (
                "provenance.json",
                provenance_document(include_scanner=False),
                "SBOM generator",
            ),
            "invalid SBOM": (
                "sbom.json",
                {"SPDX": {"SPDXID": "forged", "packages": []}},
                "SPDX SBOM",
            ),
        }
        for name, (filename, replacement, expected) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                write_json(root / filename, replacement)
                with self.assertRaisesRegex(publication.PublicationError, expected):
                    self.validate(root)

    def test_exact_provenance_material_uri_and_digest_are_mandatory(self) -> None:
        scanner_cases = {
            "same name wrong digest": provenance_document(scanner_digest="2" * 64),
            "lookalike URI": provenance_document(
                scanner_uri=(publication.SBOM_GENERATOR_PROVENANCE_URI + ".lookalike")
            ),
        }
        for name, replacement in scanner_cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                write_json(root / "provenance.json", replacement)
                with self.assertRaisesRegex(
                    publication.PublicationError, "exact SBOM generator material"
                ):
                    self.validate(root)

        for name, uri, expected in (
            (
                "Rust base",
                publication.RUST_BASE_PROVENANCE_URI,
                "exact Rust base image material",
            ),
            (
                "Python base",
                publication.PYTHON_BASE_PROVENANCE_URI,
                "exact Python base image material",
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                provenance = provenance_document()
                materials = provenance["SLSA"]["buildDefinition"][
                    "resolvedDependencies"
                ]
                material = next(item for item in materials if item["uri"] == uri)
                material["digest"] = {"sha256": "2" * 64}
                write_json(root / "provenance.json", provenance)
                with self.assertRaisesRegex(publication.PublicationError, expected):
                    self.validate(root)

    def test_runtime_manifest_lock_and_wrapper_bindings_reject_tampering(self) -> None:
        mutations = {
            "vendor_lock_sha256": "sha256:" + "7" * 64,
            "wrapper_sha256": "sha256:" + "8" * 64,
            "profile": "forged-profile",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                manifest_path = root / "runtime-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest[field] = replacement
                write_json(manifest_path, manifest, canonical=True)
                with self.assertRaisesRegex(
                    publication.PublicationError, "runtime manifest fields"
                ):
                    self.validate(root)

    def test_builder_version_evidence_is_mandatory_and_exact(self) -> None:
        mutations = {
            "buildx-version.txt": "github.com/docker/buildx v0.37.0 forged\n",
            "buildkit-inspect.txt": "BuildKit version: v0.32.0\n",
        }
        for filename, replacement in mutations.items():
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.evidence(pathlib.Path(temporary))
                (root / filename).write_text(replacement, encoding="utf-8")
                with self.assertRaises(publication.PublicationError):
                    self.validate(root)

    def test_same_buildx_version_with_different_binary_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.evidence(pathlib.Path(temporary))
            identity_path = root / "buildx-identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            self.assertEqual(publication.BUILDX_VERSION, identity["version"])
            identity["sha256"] = "sha256:" + "0" * 64
            write_json(identity_path, identity, canonical=True)
            with self.assertRaisesRegex(
                publication.PublicationError, "Buildx executable identity"
            ):
                self.validate(root)

    def test_every_external_image_linux_amd64_digest_is_bound(self) -> None:
        cases = {
            "sbom-generator-index.json": "SBOM generator linux/amd64",
            "rust-base-index.json": "Rust base linux/amd64",
            "python-base-index.json": "Python base linux/amd64",
        }
        for filename, expected in cases.items():
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.evidence(pathlib.Path(temporary))
                index_path = root / filename
                index = json.loads(index_path.read_text(encoding="utf-8"))
                index["manifests"][0]["digest"] = "sha256:" + "0" * 64
                write_json(index_path, index)
                with self.assertRaisesRegex(publication.PublicationError, expected):
                    self.validate(root)

    def test_buildkit_container_and_repo_digest_are_bound(self) -> None:
        mutations = {
            "configured image": (
                "buildkit-container.json",
                {
                    "configured_image": "moby/buildkit:latest",
                    "image_id": "sha256:" + "4" * 64,
                },
            ),
            "repository digest": (
                "buildkit-image.json",
                {
                    "image_id": "sha256:" + "4" * 64,
                    "repo_digests": ["moby/buildkit@sha256:" + "0" * 64],
                },
            ),
        }
        for name, (filename, replacement) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                write_json(root / filename, replacement)
                with self.assertRaisesRegex(publication.PublicationError, "BuildKit"):
                    self.validate(root)

    def test_evidence_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.evidence(pathlib.Path(temporary))
            with unittest.mock.patch.object(
                pathlib.Path, "is_symlink", return_value=True
            ):
                with self.assertRaisesRegex(
                    publication.PublicationError, "do not match the schema"
                ):
                    self.validate(root)

    def test_each_builder_identity_label_is_mandatory_and_exact(self) -> None:
        label_names = (
            "io.elevenid.feature-regression.probe.builder.buildx-version",
            "io.elevenid.feature-regression.probe.builder.buildx-sha256",
            "io.elevenid.feature-regression.probe.builder.buildkit-image",
            "io.elevenid.feature-regression.probe.builder.sbom-generator",
            "io.elevenid.feature-regression.probe.builder.sbom-generator-linux-amd64-digest",
            "io.elevenid.feature-regression.probe.runtime.python-base-image",
            "io.elevenid.feature-regression.probe.runtime.python-base-linux-amd64-digest",
        )
        for label in label_names:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = self.evidence(pathlib.Path(temporary))
                labels = json.loads((root / "labels.json").read_text(encoding="utf-8"))
                labels[label] = "forged"
                write_json(root / "labels.json", labels)
                with self.assertRaisesRegex(publication.PublicationError, label):
                    self.validate(root)

    def test_every_provenance_build_argument_is_mandatory_and_exact(self) -> None:
        for argument in publication._expected_build_arguments(BUNDLE):
            with (
                self.subTest(argument=argument),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.evidence(pathlib.Path(temporary))
                provenance = json.loads(
                    (root / "provenance.json").read_text(encoding="utf-8")
                )
                args = provenance["SLSA"]["buildDefinition"]["externalParameters"][
                    "request"
                ]["args"]
                args[f"build-arg:{argument}"] = "forged"
                write_json(root / "provenance.json", provenance)
                with self.assertRaisesRegex(publication.PublicationError, argument):
                    self.validate(root)

    def test_workflow_policy_pins_every_privileged_builder_identity(self) -> None:
        self.assertEqual(PINNED_BUILDERS["buildx_version"], publication.BUILDX_VERSION)
        self.assertEqual(
            PINNED_BUILDERS["buildx_linux_amd64_sha256"],
            publication.BUILDX_LINUX_AMD64_SHA256,
        )
        self.assertEqual(
            PINNED_BUILDERS["buildkit_version"], publication.BUILDKIT_VERSION
        )
        self.assertEqual(PINNED_BUILDERS["buildkit_image"], publication.BUILDKIT_IMAGE)
        self.assertEqual(PINNED_BUILDERS["sbom_generator"], publication.SBOM_GENERATOR)
        self.assertEqual(
            "rust:1.95-bookworm@sha256:"
            "6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1",
            publication.RUST_BASE_IMAGE,
        )
        self.assertEqual(
            "sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb",
            publication.RUST_BASE_LINUX_AMD64_DIGEST,
        )
        self.assertEqual(
            "python:3.11.16-bookworm@sha256:"
            "b99029c95d3d37fb1e4e76d287f7984373dca77c665885986e31b2c95260c13c",
            publication.PYTHON_BASE_IMAGE,
        )
        self.assertEqual(
            "sha256:00f0ecbf74ff8f915020d5a40c4bc6a83f46cd7b83f47db51c7e204f0d8a3ec2",
            publication.PYTHON_BASE_LINUX_AMD64_DIGEST,
        )
        root = pathlib.Path(__file__).parents[1]
        workflow = yaml.safe_load(
            (root / ".github" / "workflows" / "publish-rust-probe-runtime.yml")
            .read_text(encoding="utf-8")
            .replace("\non:\n", "\ntrigger:\n", 1)
        )
        self.assertEqual(
            {
                "RUST_BUILDX_VERSION": publication.BUILDX_VERSION,
                "RUST_BUILDX_LINUX_AMD64_SHA256": (
                    publication.BUILDX_LINUX_AMD64_SHA256
                ),
                "RUST_BUILDX_ASSET_URL": (
                    "https://github.com/docker/buildx/releases/download/v0.37.1/"
                    "buildx-v0.37.1.linux-amd64"
                ),
                "RUST_BUILDKIT_VERSION": publication.BUILDKIT_VERSION,
                "RUST_BUILDKIT_IMAGE": publication.BUILDKIT_IMAGE,
                "RUST_SBOM_GENERATOR": publication.SBOM_GENERATOR,
                "RUST_SBOM_GENERATOR_LINUX_AMD64_DIGEST": (
                    publication.SBOM_GENERATOR_LINUX_AMD64_DIGEST
                ),
                "RUST_TOOLCHAIN_BASE_IMAGE": publication.RUST_BASE_IMAGE,
                "RUST_TOOLCHAIN_BASE_LINUX_AMD64_DIGEST": (
                    publication.RUST_BASE_LINUX_AMD64_DIGEST
                ),
                "RUST_PYTHON_BASE_IMAGE": publication.PYTHON_BASE_IMAGE,
                "RUST_PYTHON_BASE_LINUX_AMD64_DIGEST": (
                    publication.PYTHON_BASE_LINUX_AMD64_DIGEST
                ),
            },
            workflow["env"],
        )
        steps = workflow["jobs"]["publish"]["steps"]
        self.assertFalse(
            any("docker/setup-buildx-action@" in step.get("uses", "") for step in steps)
        )
        publisher_step = next(
            step
            for step in steps
            if step.get("name") == "Build and publish content-addressed runtime"
        )
        publisher = publisher_step["run"]
        checksum_check = 'test "$buildx_sha256" = "$RUST_BUILDX_LINUX_AMD64_SHA256"'
        self.assertIn("$RUST_BUILDX_ASSET_URL", publisher)
        self.assertIn(checksum_check, publisher)
        self.assertIn("buildx-identity.json", publisher)
        self.assertLess(publisher.index(checksum_check), publisher.index("chmod 0555"))
        self.assertLess(
            publisher.index(checksum_check), publisher.index("docker buildx version")
        )
        self.assertIn(
            '--driver-opt "image=$RUST_BUILDKIT_IMAGE"',
            publisher,
        )
        self.assertIn("buildkit-container.json", publisher)
        self.assertIn("buildkit-image.json", publisher)
        self.assertIn("sbom-generator-index.json", publisher)
        self.assertIn("rust-base-index.json", publisher)
        self.assertIn("python-base-index.json", publisher)
        self.assertIn("--provenance=mode=max,version=v1", publisher)
        self.assertIn('--sbom="generator=$RUST_SBOM_GENERATOR"', publisher)
        self.assertIn("--platform linux/amd64", publisher)
        for argument, variable in {
            "BUILDX_VERSION": "RUST_BUILDX_VERSION",
            "BUILDX_SHA256": "RUST_BUILDX_LINUX_AMD64_SHA256",
            "BUILDKIT_IMAGE": "RUST_BUILDKIT_IMAGE",
            "SBOM_GENERATOR": "RUST_SBOM_GENERATOR",
            "SBOM_GENERATOR_LINUX_AMD64_DIGEST": (
                "RUST_SBOM_GENERATOR_LINUX_AMD64_DIGEST"
            ),
            "PYTHON_BASE_IMAGE": "RUST_PYTHON_BASE_IMAGE",
            "PYTHON_BASE_LINUX_AMD64_DIGEST": ("RUST_PYTHON_BASE_LINUX_AMD64_DIGEST"),
        }.items():
            self.assertIn(f'--build-arg "{argument}=${variable}"', publisher)

        dockerfile = (root / "runtime" / "rust-cargo" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertEqual(1, dockerfile.count(f"FROM {publication.RUST_BASE_IMAGE}"))
        self.assertEqual(1, dockerfile.count(f"FROM {publication.PYTHON_BASE_IMAGE}"))
        for package_manager in (
            "apt-get",
            " apt ",
            "apk ",
            "dnf ",
            "yum ",
            "microdnf ",
        ):
            self.assertNotIn(package_manager, dockerfile)
        for label, argument in {
            "buildx-version": "BUILDX_VERSION",
            "buildx-sha256": "BUILDX_SHA256",
            "buildkit-image": "BUILDKIT_IMAGE",
            "sbom-generator": "SBOM_GENERATOR",
            "sbom-generator-linux-amd64-digest": ("SBOM_GENERATOR_LINUX_AMD64_DIGEST"),
        }.items():
            self.assertIn(
                f'io.elevenid.feature-regression.probe.builder.{label}="${argument}"',
                dockerfile,
            )
        for label, argument in {
            "python-base-image": "PYTHON_BASE_IMAGE",
            "python-base-linux-amd64-digest": "PYTHON_BASE_LINUX_AMD64_DIGEST",
        }.items():
            self.assertIn(
                f'io.elevenid.feature-regression.probe.runtime.{label}="${argument}"',
                dockerfile,
            )

    @unittest.skip(
        "a disposable publish mutates an external registry; the main-only hosted "
        "publisher is the authoritative end-to-end integration test"
    )
    def test_live_disposable_registry_publication_cycle(self) -> None:
        self.fail("hosted-only integration test must remain skipped")

    @unittest.skipUnless(
        os.environ.get("ELEVENID_LIVE_REGISTRY_TEST") == "1",
        "opt-in read-only registry verification; hosted publisher is authoritative",
    )
    def test_live_pinned_builder_manifests_resolve_without_credentials(self) -> None:
        for reference in (
            publication.BUILDKIT_IMAGE,
            publication.SBOM_GENERATOR,
            publication.PYTHON_BASE_IMAGE,
        ):
            with self.subTest(reference=reference):
                result = subprocess.run(
                    ["docker", "buildx", "imagetools", "inspect", reference],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr.decode())
                expected = reference.rsplit("@", 1)[1]
                self.assertRegex(result.stdout.decode(), rf"(?m)^Digest:\s+{expected}$")
        for reference, expected_child in (
            (publication.RUST_BASE_IMAGE, publication.RUST_BASE_LINUX_AMD64_DIGEST),
            (
                publication.PYTHON_BASE_IMAGE,
                publication.PYTHON_BASE_LINUX_AMD64_DIGEST,
            ),
            (
                publication.SBOM_GENERATOR,
                publication.SBOM_GENERATOR_LINUX_AMD64_DIGEST,
            ),
        ):
            with self.subTest(reference=reference, expected_child=expected_child):
                result = subprocess.run(
                    [
                        "docker",
                        "buildx",
                        "imagetools",
                        "inspect",
                        reference,
                        "--raw",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr.decode())
                image_index = json.loads(result.stdout)
                self.assertTrue(
                    any(
                        manifest.get("platform")
                        == {"architecture": "amd64", "os": "linux"}
                        and manifest.get("digest") == expected_child
                        for manifest in image_index["manifests"]
                    )
                )
        result = subprocess.run(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                publication.BUILDKIT_IMAGE,
                "--format",
                "{{json .Provenance}}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode())
        provenance = json.loads(result.stdout)
        slsa_payloads = [
            value["SLSA"]
            for value in provenance.values()
            if isinstance(value, dict) and isinstance(value.get("SLSA"), dict)
        ]
        if isinstance(provenance.get("SLSA"), dict):
            slsa_payloads.append(provenance["SLSA"])
        self.assertTrue(slsa_payloads)
        self.assertTrue(
            any(
                material.get("uri") == publication.SBOM_GENERATOR_PROVENANCE_URI
                and material.get("digest")
                == {"sha256": publication.SBOM_GENERATOR.rsplit("@sha256:", 1)[1]}
                for payload in slsa_payloads
                for material in payload["buildDefinition"]["resolvedDependencies"]
            )
        )


if __name__ == "__main__":
    unittest.main()
