from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import rust_runtime_bundle as bundle


VALID_BUNDLE = {
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


class RustRuntimeBundleTests(unittest.TestCase):
    def catalog(self, root: pathlib.Path, record: dict[str, str]) -> pathlib.Path:
        path = root / "bundles.json"
        path.write_text(
            json.dumps(
                {
                    "bundles": [record],
                    "schema": "elevenid.rust-cargo-runtime-bundles/v1",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        return path

    def test_checked_in_catalog_activates_no_publishable_bundle(self) -> None:
        path = (
            pathlib.Path(__file__).parents[1]
            / "runtime"
            / "rust-cargo"
            / "bundles.json"
        )
        with self.assertRaisesRegex(bundle.BundleError, "not uniquely activated"):
            bundle.load_bundle(path, "marty-ui")

    def test_exact_revision_paths_and_digests_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            probe = root / ".github" / "feature-regression" / "rust-probe"
            probe.mkdir(parents=True)
            manifest = probe / "Cargo.toml"
            lock = probe / "Cargo.lock"
            subject = probe / "behavior_subject.rs"
            manifest.write_bytes(
                b"[package]\nname='probe'\n"
                b"[[bin]]\nname='elevenid-feature-regression-probe'\n"
                b"path='behavior_subject.rs'\n"
            )
            lock.write_bytes(b"version = 3\n")
            subject.write_bytes(b"fn main() {}\n")
            record = {
                "id": "marty-ui",
                "repository": "ElevenID/marty-ui",
                "revision": "a" * 40,
                "manifest_path": manifest.relative_to(root).as_posix(),
                "manifest_sha256": "sha256:"
                + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "lock_path": lock.relative_to(root).as_posix(),
                "lock_sha256": "sha256:"
                + hashlib.sha256(lock.read_bytes()).hexdigest(),
                "subject_path": subject.relative_to(root).as_posix(),
                "subject_sha256": "sha256:"
                + hashlib.sha256(subject.read_bytes()).hexdigest(),
            }
            catalog = root / "bundles.json"
            catalog.write_text(
                json.dumps(
                    {
                        "bundles": [record],
                        "schema": "elevenid.rust-cargo-runtime-bundles/v1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            self.assertEqual(record, bundle.load_bundle(catalog, "marty-ui"))
            bundle.verify_target(root, record)
            with self.assertRaisesRegex(bundle.BundleError, "digest does not match"):
                bundle.verify_file(root, record["lock_path"], "sha256:" + "0" * 64)

            record["manifest_path"] = "../Cargo.toml"
            catalog.write_text(
                json.dumps(
                    {
                        "bundles": [record],
                        "schema": "elevenid.rust-cargo-runtime-bundles/v1",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(bundle.BundleError, "repository-relative"):
                bundle.load_bundle(catalog, "marty-ui")

    def test_probe_binary_cannot_be_redirected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            probe = root / ".github" / "feature-regression" / "rust-probe"
            probe.mkdir(parents=True)
            manifest = probe / "Cargo.toml"
            lock = probe / "Cargo.lock"
            subject = probe / "behavior_subject.rs"
            manifest.write_text(
                "[package]\nname='probe'\n"
                "[[bin]]\nname='elevenid-feature-regression-probe'\n"
                "path='../forged.rs'\n",
                encoding="utf-8",
            )
            lock.write_text("version = 3\n", encoding="utf-8")
            subject.write_text("fn main() {}\n", encoding="utf-8")
            record = {
                "manifest_path": manifest.relative_to(root).as_posix(),
                "manifest_sha256": "sha256:"
                + hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "lock_path": lock.relative_to(root).as_posix(),
                "lock_sha256": "sha256:"
                + hashlib.sha256(lock.read_bytes()).hexdigest(),
                "subject_path": subject.relative_to(root).as_posix(),
                "subject_sha256": "sha256:"
                + hashlib.sha256(subject.read_bytes()).hexdigest(),
            }
            with self.assertRaisesRegex(bundle.BundleError, "identify the subject"):
                bundle.verify_target(root, record)

    def test_paths_reject_controls_unicode_backslashes_and_oversize_values(
        self,
    ) -> None:
        invalid = (
            "path/with\nnewline",
            "path/with\rcarriage-return",
            "path/with\ttab",
            "path/with\0nul",
            "path/with\x7fdelete",
            "path/unicodé",
            r"path\ambiguous",
            "path//empty",
            "path/./dot",
            "path/../escape",
            "a" * 513,
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(bundle.BundleError, "safe.*ASCII path"):
                    bundle._relative(value, "test path")

    def test_github_output_has_exact_single_line_keys_and_rejects_injection(
        self,
    ) -> None:
        output = bundle.github_output_bytes(dict(VALID_BUNDLE)).decode("ascii")
        lines = output.splitlines()
        expected_names = [name for name, _ in bundle.GITHUB_OUTPUT_BINDINGS]
        self.assertEqual(expected_names, [line.split("=", 1)[0] for line in lines])
        self.assertEqual(len(expected_names), len(lines))
        self.assertTrue(output.endswith("\n"))
        self.assertNotIn("\r", output)
        for _, bundle_name in bundle.GITHUB_OUTPUT_BINDINGS:
            with self.subTest(bundle_name=bundle_name):
                malicious = dict(VALID_BUNDLE)
                malicious[bundle_name] += "\nforged_output=accepted"
                with self.assertRaisesRegex(bundle.BundleError, "unsafe"):
                    bundle.github_output_bytes(malicious)

    def test_cli_appends_only_validated_github_output_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            catalog = self.catalog(root, dict(VALID_BUNDLE))
            github_output = root / "github-output"
            result = subprocess.run(
                [
                    sys.executable,
                    str(pathlib.Path(bundle.__file__)),
                    "marty-ui",
                    "--catalog",
                    str(catalog),
                    "--github-output",
                    str(github_output),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr.decode())
            self.assertEqual(
                bundle.github_output_bytes(dict(VALID_BUNDLE)),
                github_output.read_bytes(),
            )

    def test_every_github_output_source_is_strictly_validated_by_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for _, bundle_name in bundle.GITHUB_OUTPUT_BINDINGS:
                with self.subTest(bundle_name=bundle_name):
                    malicious = dict(VALID_BUNDLE)
                    malicious[bundle_name] += "\nforged_output=accepted"
                    catalog = self.catalog(root, malicious)
                    with self.assertRaises(bundle.BundleError):
                        bundle.load_bundle(catalog, "marty-ui")

    def test_target_files_must_not_be_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "subject.rs"
            path.write_text("fn main() {}\n", encoding="utf-8")
            with mock.patch.object(pathlib.Path, "is_symlink", return_value=True):
                with self.assertRaisesRegex(bundle.BundleError, "non-symlink"):
                    bundle.verify_file(
                        pathlib.Path(temporary), "subject.rs", "sha256:" + "0" * 64
                    )

    def test_publisher_is_main_gated_attested_and_proves_anonymous_access(self) -> None:
        root = pathlib.Path(__file__).parents[1]
        workflow = (
            root / ".github" / "workflows" / "publish-rust-probe-runtime.yml"
        ).read_text(encoding="utf-8")
        dockerfile = (root / "runtime" / "rust-cargo" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        wrapper = (root / "runtime" / "rust-cargo" / "run-rust-probe").read_text(
            encoding="utf-8"
        )
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertNotIn("pull_request", workflow)
        self.assertIn("timeout-minutes: 45", workflow)
        self.assertIn("permissions:\n  contents: read\n  packages: write", workflow)
        self.assertIn("--provenance=mode=max", workflow)
        self.assertIn("--metadata-file", workflow)
        self.assertIn("{{json .Provenance}}", workflow)
        self.assertIn("{{json .SBOM}}", workflow)
        self.assertIn('anonymous_config="$(mktemp -d', workflow)
        self.assertIn('export DOCKER_CONFIG="$anonymous_config"', workflow)
        self.assertIn("docker logout ghcr.io", workflow)
        self.assertIn('docker image rm --force "$image_digest"', workflow)
        self.assertIn('docker pull "$image_digest"', workflow)
        self.assertIn("--pull=never --network=none --read-only", workflow)
        self.assertIn("GHCR package must be public", workflow)
        self.assertIn("rust-runtime-publication-${{ github.run_id }}", workflow)
        self.assertLess(
            workflow.index('export DOCKER_CONFIG="$anonymous_config"'),
            workflow.index('if ! docker pull "$image_digest"'),
        )
        self.assertLess(
            workflow.index('if ! docker pull "$image_digest"'),
            workflow.index("printf 'image=%s\\n'"),
        )
        self.assertNotIn("# syntax=", dockerfile)
        self.assertEqual(2, dockerfile.count("FROM rust:1.95-bookworm@sha256:"))
        self.assertIn("org.opencontainers.image.source", dockerfile)
        for binding in (
            "repository",
            "revision",
            "manifest",
            "manifest-sha256",
            "lock",
            "lock-sha256",
            "subject",
            "subject-sha256",
        ):
            self.assertIn(f"io.elevenid.feature-regression.probe.{binding}", dockerfile)
        self.assertIn("cargo-config.toml", wrapper)
        self.assertIn("--frozen", wrapper)
        self.assertNotIn("curl ", wrapper)


if __name__ == "__main__":
    unittest.main()
