from __future__ import annotations

import copy
import hashlib
import base64
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts import rust_runtime_source_access as access
from scripts import feature_regression_review as review


IMAGE = "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
REVISION = "c" * 40
SOURCE_REVISION = "d" * 40
LOCK = (
    """version = 4
[[package]]
name = "local-probe"
version = "0.0.0"
[[package]]
name = "private-library"
version = "1.0.0"
source = "git+https://github.com/ElevenID/example-private?rev=%s#%s"
[[package]]
name = "public-registry-library"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    % (SOURCE_REVISION, SOURCE_REVISION)
).encode()


class SourceAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        access._REMOTE_CATALOGS.clear()
        self.addCleanup(access._REMOTE_CATALOGS.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "access.json"
        self.grant = {
            "repository": "ElevenID/example",
            "revision": REVISION,
            "runtime_image": IMAGE,
            "runtime_manifest_sha256": MANIFEST,
            "lock_sha256": "sha256:" + hashlib.sha256(LOCK).hexdigest(),
            "git_sources": [
                {"repository": "ElevenID/example-private", "revision": SOURCE_REVISION}
            ],
        }

    def catalog(self, grants: list[dict]) -> None:
        self.path.write_text(
            json.dumps(
                {"schema": "elevenid.rust-runtime-source-access/v1", "grants": grants}
            ),
            encoding="utf-8",
        )

    def require(self, **changes: object) -> None:
        args = dict(
            repository="ElevenID/example",
            revision=REVISION,
            runtime_image=IMAGE,
            runtime_manifest_sha256=MANIFEST,
            lock=LOCK,
        )
        args.update(changes)
        original = access.load_grants
        with mock.patch.object(
            access, "load_grants", side_effect=lambda: original(self.path)
        ):
            access.require_access(**args)

    def test_protected_catalog_initially_grants_no_access(self) -> None:
        self.assertEqual([], access.load_grants())

    def test_exact_candidate_and_entire_git_closure_are_admitted(self) -> None:
        self.catalog([self.grant])
        self.require()
        self.require(repository="elevenid/EXAMPLE")

    def test_image_activation_alone_does_not_grant_candidate_source_access(
        self,
    ) -> None:
        self.catalog([])
        with self.assertRaisesRegex(access.SourceAccessError, "not admitted"):
            self.require()

    def test_other_revision_repository_image_manifest_or_lock_is_refused(self) -> None:
        self.catalog([self.grant])
        variants = [
            dict(revision="e" * 40),
            dict(repository="ElevenID/other"),
            dict(runtime_image=IMAGE[:-1] + "f"),
            dict(runtime_manifest_sha256="sha256:" + "f" * 64),
            dict(lock=LOCK + b"\n"),
        ]
        for variant in variants:
            with self.subTest(variant=list(variant)):
                with self.assertRaises(access.SourceAccessError):
                    self.require(**variant)

    def test_missing_extra_or_different_source_revision_is_refused(self) -> None:
        for sources in [
            [],
            [{"repository": "ElevenID/other", "revision": SOURCE_REVISION}],
            [{"repository": "ElevenID/example-private", "revision": "e" * 40}],
            self.grant["git_sources"]
            + [{"repository": "ElevenID/extra", "revision": SOURCE_REVISION}],
        ]:
            grant = dict(self.grant, git_sources=sources)
            self.catalog([grant])
            with self.subTest(sources=sources):
                with self.assertRaisesRegex(access.SourceAccessError, "source closure"):
                    self.require()

    def test_same_repository_can_have_multiple_explicit_locked_revisions(self) -> None:
        second = "e" * 40
        lock = (
            LOCK
            + (
                '\n[[package]]\nname="second"\nversion="1.0.0"\nsource="git+https://github.com/ElevenID/example-private#%s"\n'
                % second
            ).encode()
        )
        self.assertEqual(
            {
                ("elevenid/example-private", SOURCE_REVISION),
                ("elevenid/example-private", second),
            },
            access.locked_git_sources(lock),
        )

    def test_unused_locked_patch_source_still_requires_admission(self) -> None:
        lock = (
            LOCK
            + (
                '\n[[patch.unused]]\nname="unused"\nversion="1.0.0"\n'
                'source="git+https://github.com/ElevenID/other-private#'
                + "e" * 40
                + '"\n'
            ).encode()
        )
        self.assertIn(
            ("elevenid/other-private", "e" * 40), access.locked_git_sources(lock)
        )
        grant = dict(
            self.grant, lock_sha256="sha256:" + hashlib.sha256(lock).hexdigest()
        )
        self.catalog([grant])
        with self.assertRaisesRegex(access.SourceAccessError, "source closure"):
            self.require(lock=lock)

    def test_unknown_registry_and_unsafe_git_sources_are_refused(self) -> None:
        sources = [
            "registry+https://unreviewed.invalid/index",
            "git+http://github.com/ElevenID/example-private#" + SOURCE_REVISION,
            "git+https://user@github.com/ElevenID/example-private#" + SOURCE_REVISION,
            "git+https://github.com:443/ElevenID/example-private#" + SOURCE_REVISION,
            "git+https://github.com/ElevenID/example-private#main",
            "git+https://evil.invalid/ElevenID/example-private#" + SOURCE_REVISION,
            "git+https://github.com/ElevenID/%65xample-private#" + SOURCE_REVISION,
        ]
        for source in sources:
            lock = (
                '[[package]]\nname="fixture"\nversion="1.0.0"\nsource="%s"\n' % source
            ).encode()
            with self.subTest(source=source):
                with self.assertRaises(access.SourceAccessError):
                    access.locked_git_sources(lock)

    def test_malformed_duplicate_wildcard_and_mutable_grants_are_refused(self) -> None:
        variants = [
            dict(self.grant, revision="*"),
            dict(self.grant, runtime_image=IMAGE.split("@")[0] + ":latest"),
            dict(self.grant, lock_sha256="sha256:bad"),
            dict(self.grant, unexpected=True),
            dict(self.grant, git_sources=self.grant["git_sources"] * 2),
        ]
        for grant in variants:
            self.catalog([grant])
            with self.subTest(fields=list(grant)):
                with self.assertRaises(access.SourceAccessError):
                    access.load_grants(self.path)
        self.catalog([self.grant, copy.deepcopy(self.grant)])
        with self.assertRaisesRegex(access.SourceAccessError, "duplicated"):
            access.load_grants(self.path)
        self.path.write_text(
            '{"schema":"one","schema":"two","grants":[]}', encoding="utf-8"
        )
        with self.assertRaisesRegex(access.SourceAccessError, "duplicate fields"):
            access.load_grants(self.path)

    def test_restricted_repository_namespace_is_explicit(self) -> None:
        self.assertTrue(access.is_restricted_image(IMAGE))
        self.assertFalse(access.is_restricted_image(IMAGE.replace("-restricted", "")))
        self.assertFalse(
            access.is_restricted_image("ghcr.io/other/runtime@sha256:" + "a" * 64)
        )

    def remote_catalog(self, grants):
        raw = json.dumps(
            {"schema": "elevenid.rust-runtime-source-access/v1", "grants": grants},
            sort_keys=True,
        ).encode()
        return {
            "type": "file",
            "path": "runtime/rust-cargo/source-access.json",
            "encoding": "base64",
            "content": base64.b64encode(raw).decode(),
            "size": len(raw),
            "sha": hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest(),
        }

    def candidate(self):
        return dict(
            repository="ElevenID/example",
            revision=REVISION,
            runtime_image=IMAGE,
            runtime_manifest_sha256=MANIFEST,
            lock=LOCK,
        )

    def test_grant_data_can_advance_without_changing_the_frozen_runner_revision(
        self,
    ) -> None:
        first, second = "1" * 40, "2" * 40
        state = {
            "main": first,
            "catalogs": {
                first: self.remote_catalog([self.grant]),
                second: self.remote_catalog([self.grant]),
            },
        }

        def api(path, token):
            if path == "git/ref/heads/main":
                return {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": state["main"]},
                }
            if path.startswith("contents/"):
                return state["catalogs"][path.split("?ref=")[1]]
            if path in {
                "compare/" + first + "..." + second,
                "compare/" + first + "..." + "3" * 40,
            }:
                return {"status": "ahead"}
            self.fail("unexpected policy API request")

        with (
            mock.patch.object(access, "_policy_api", side_effect=api),
            mock.patch.object(
                access,
                "load_grants",
                side_effect=AssertionError(
                    "frozen local catalog must not authorize future candidates"
                ),
            ),
        ):
            proof = access.admit_from_protected_main(token="", **self.candidate())
            self.assertEqual(first, proof["policy_revision"])
            state["main"] = second
            access.verify_protected_admission(proof, token="", **self.candidate())
            newer = access.admit_from_protected_main(token="", **self.candidate())
            self.assertEqual(second, newer["policy_revision"])
            # A later protected removal revokes even the historical proof.
            state["main"] = "3" * 40
            state["catalogs"]["3" * 40] = self.remote_catalog([])
            with self.assertRaisesRegex(access.SourceAccessError, "not admitted"):
                access.verify_protected_admission(proof, token="", **self.candidate())

    def test_unmerged_policy_and_changed_catalog_blob_are_refused(self) -> None:
        first, second = "1" * 40, "2" * 40
        catalog = self.remote_catalog([self.grant])

        def api(path, token):
            if path == "git/ref/heads/main":
                return {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": second},
                }
            if path.startswith("contents/"):
                return catalog
            return {"status": "diverged"}

        with mock.patch.object(access, "_policy_api", side_effect=api):
            proof = access.admit_from_protected_main(token="", **self.candidate())
            proof["policy_revision"] = first
            with self.assertRaisesRegex(access.SourceAccessError, "not integrated"):
                access.verify_protected_admission(proof, token="", **self.candidate())
            catalog["sha"] = "0" * 40
            access._REMOTE_CATALOGS.clear()
            with self.assertRaisesRegex(access.SourceAccessError, "bytes differ"):
                access.admit_from_protected_main(token="", **self.candidate())

    def test_reviewer_refuses_artifact_before_run_or_download_without_admission(
        self,
    ) -> None:
        fetch_run, fetch_jobs, fetch_artifacts, download = (
            mock.Mock() for _ in range(4)
        )
        producer = SimpleNamespace(
            runtime_image=IMAGE,
            rust_build=SimpleNamespace(
                runtime_manifest_sha256=MANIFEST,
                lock_path=".github/feature-regression/probe/Cargo.lock",
            ),
        )
        with (
            mock.patch.object(
                access,
                "admit_from_protected_main",
                side_effect=access.SourceAccessError("not admitted"),
            ),
            self.assertRaisesRegex(review.EvidenceError, "not admitted"),
        ):
            review._validate_artifact_observation(
                "artifact-observation:ElevenID/example@123:example",
                "fixture",
                expected_repository="ElevenID/example",
                expected_commit=REVISION,
                expected_phase="after",
                producer=producer,
                operation_id="fixture",
                case_id="fixture",
                dimension="public_status",
                expected_value="HTTP 200",
                fetch_content=lambda *_: LOCK,
                fetch_run=fetch_run,
                fetch_jobs=fetch_jobs,
                fetch_artifacts=fetch_artifacts,
                download_artifact=download,
            )
        for operation in (fetch_run, fetch_jobs, fetch_artifacts, download):
            operation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
