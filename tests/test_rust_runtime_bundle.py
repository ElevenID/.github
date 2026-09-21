from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

from scripts import rust_runtime_bundle as bundle


class RustRuntimeBundleTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
