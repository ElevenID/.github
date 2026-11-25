from __future__ import annotations

import copy
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import yaml

from scripts import rust_runtime_registry as registry
from scripts import feature_regression_review as review


TOKEN = "fixture-credential-only"
IMAGE = "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "a" * 64
REVISION = "b" * 40


class RegistryTests(unittest.TestCase):
    def test_metadata_cli_emits_only_normalized_proof_and_consumes_token(self) -> None:
        metadata = {
            "name": registry.PACKAGE,
            "owner": "ElevenID",
            "package_type": "container",
            "visibility": "private",
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "package.json"
            with (
                mock.patch.dict(
                    os.environ, {"RUST_RUNTIME_PACKAGE_METADATA_TOKEN": TOKEN}
                ),
                mock.patch.object(
                    registry, "require_private_package", return_value=metadata
                ) as check,
            ):
                self.assertEqual(
                    0, registry.main(["check-private-package", "--output", str(output)])
                )
                check.assert_called_once_with(TOKEN)
                self.assertNotIn("RUST_RUNTIME_PACKAGE_METADATA_TOKEN", os.environ)
            self.assertEqual(metadata, json.loads(output.read_text(encoding="utf-8")))
            self.assertNotIn(TOKEN, output.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.event_path = pathlib.Path(self.temporary.name) / "event.json"
        self.event = {
            "repository": {"full_name": "ElevenID/example"},
            "number": 12,
            "pull_request": {
                "head": {"sha": REVISION, "repo": {"full_name": "ElevenID/example"}},
                "base": {"repo": {"full_name": "ElevenID/example"}},
                "user": {"login": "author", "type": "User"},
            },
        }
        self.env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "ElevenID/example",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/12/merge",
            "GITHUB_ACTOR": "author",
            "GITHUB_EVENT_PATH": str(self.event_path),
        }

    def context(self, *, event=None, env=None, event_name="pull_request") -> None:
        self.event_path.write_text(
            json.dumps(self.event if event is None else event), encoding="utf-8"
        )
        registry.require_execution_context(
            repository="ElevenID/example",
            revision=REVISION,
            event_name=event_name,
            environment=self.env if env is None else env,
        )

    def test_internal_exact_head_and_current_main_are_authorized(self) -> None:
        self.context()
        for event_name in ("push", "schedule", "workflow_dispatch"):
            self.context(
                event_name=event_name,
                env={
                    **self.env,
                    "GITHUB_EVENT_NAME": event_name,
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": REVISION,
                },
            )

    def test_restricted_caller_maps_explicit_package_secrets_without_job_token_access(
        self,
    ) -> None:
        fields = dict(
            subject_args=(),
            subject_env={},
            rust_build=None,
            central_workflow_sha="a" * 40,
            workflow_path=".github/workflows/observations.yml",
            harness_path="harness.py",
            harness_sha256="sha256:" + "b" * 64,
            subject_path="subject.py",
            subject_runtime="python",
            subject_sha256="sha256:" + "c" * 64,
            runtime_image="python@sha256:" + "d" * 64,
            job_name="fixture",
            artifact_name_prefix="fixture",
            observation_path="observations.json",
        )
        public = yaml.safe_load(
            review._expected_producer_workflow(SimpleNamespace(**fields))
        )
        private = yaml.safe_load(
            review._expected_producer_workflow(
                SimpleNamespace(**{**fields, "runtime_image": IMAGE})
            )
        )
        self.assertNotIn("packages", public["permissions"])
        self.assertNotIn("packages", private["permissions"])
        self.assertNotIn("secrets", public["jobs"]["behavior-observations"])
        self.assertEqual(
            {
                name: "${{ secrets." + name + " }}"
                for name in (
                    "RUST_RUNTIME_PACKAGE_READ_TOKEN",
                    "RUST_RUNTIME_PACKAGE_USERNAME",
                )
            },
            private["jobs"]["behavior-observations"]["secrets"],
        )
        self.assertIn(
            "feature-regression-observation-producer-restricted.yml@",
            private["jobs"]["behavior-observations"]["uses"],
        )
        root = pathlib.Path(__file__).parents[1]
        workflow = yaml.safe_load(
            (
                root
                / ".github/workflows/feature-regression-observation-producer-restricted.yml"
            ).read_text(encoding="utf-8")
        )
        self.assertNotIn("packages", workflow["permissions"])
        self.assertEqual(
            {"RUST_RUNTIME_PACKAGE_READ_TOKEN", "RUST_RUNTIME_PACKAGE_USERNAME"},
            set(workflow.get("on", workflow.get(True))["workflow_call"]["secrets"]),
        )
        jobs = workflow["jobs"]
        self.assertEqual({"generate"}, set(jobs))
        token_steps = [
            step
            for step in jobs["generate"]["steps"]
            if "RUST_RUNTIME_PULL_TOKEN" in step.get("env", {})
        ]
        self.assertEqual(1, len(token_steps))
        self.assertEqual(
            "${{ secrets.RUST_RUNTIME_PACKAGE_READ_TOKEN }}",
            token_steps[0]["env"]["RUST_RUNTIME_PULL_TOKEN"],
        )
        self.assertIn("feature_regression_observation_runner.py", token_steps[0]["run"])

    def test_restricted_publisher_uses_private_caller_job_token(self) -> None:
        root = pathlib.Path(__file__).parents[1]
        workflow = yaml.safe_load(
            (
                root / ".github/workflows/publish-restricted-rust-probe-runtime.yml"
            ).read_text(encoding="utf-8")
        )
        self.assertNotIn("packages", workflow["permissions"])
        job = workflow["jobs"]["publish"]
        self.assertEqual("write", job["permissions"]["packages"])
        self.assertIn("feature-regression-private-publisher", job["if"])
        self.assertIn("workflow_dispatch", job["if"])
        steps = [step for step in job["steps"] if "GHCR_TOKEN" in step.get("env", {})]
        self.assertEqual(2, len(steps))
        for step in steps:
            self.assertEqual(
                "${{ github.token }}",
                step["env"]["GHCR_TOKEN"],
            )
            self.assertEqual(
                "${{ github.actor }}",
                step["env"]["GHCR_USERNAME"],
            )
            self.assertIn('--username "$GHCR_USERNAME" --password-stdin', step["run"])
        self.assertNotIn("RUST_RUNTIME_PACKAGE_WRITE_TOKEN", str(workflow))
        self.assertNotIn(
            "org.opencontainers.image.source",
            (root / "runtime/rust-cargo/Dockerfile.restricted").read_text(),
        )

    def test_missing_package_credential_has_no_job_token_fallback(self) -> None:
        run = mock.Mock()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": TOKEN}):
            with self.assertRaises(registry.RegistryAccessError):
                with registry.private_pull_environment(
                    docker="docker",
                    image=IMAGE,
                    token="",
                    actor="package-reader",
                    run_process=run,
                ):
                    self.fail("missing package PAT was accepted")
        run.assert_not_called()

    def test_forks_bots_wrong_event_revision_or_ref_are_refused(self) -> None:
        mutations = [
            lambda e: e["pull_request"]["head"]["repo"].update(
                full_name="outsider/example"
            ),
            lambda e: e["pull_request"]["base"]["repo"].update(
                full_name="outsider/example"
            ),
            lambda e: e["pull_request"]["head"].update(sha="c" * 40),
            lambda e: e["pull_request"]["user"].update(login="dependabot[bot]"),
            lambda e: e["pull_request"]["user"].update(type="Bot"),
            lambda e: e["pull_request"].update(user={}),
            lambda e: e.update(repository={"full_name": "outsider/example"}),
        ]
        for mutate in mutations:
            event = copy.deepcopy(self.event)
            mutate(event)
            with self.subTest(mutation=mutations.index(mutate)):
                with self.assertRaises(registry.RegistryAccessError):
                    self.context(event=event)
        for change in (
            {"GITHUB_ACTOR": "dependabot[bot]"},
            {"GITHUB_TRIGGERING_ACTOR": "dependabot[bot]"},
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_ACTIONS": "false"},
        ):
            with self.subTest(change=change):
                with self.assertRaises(registry.RegistryAccessError):
                    self.context(env={**self.env, **change})

    def test_baseline_cannot_read_private_source_from_another_revision(self) -> None:
        with self.assertRaises(registry.RegistryAccessError):
            self.context(
                event_name="push",
                env={
                    **self.env,
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "c" * 40,
                },
            )

    def metadata(self, document: object) -> mock.Mock:
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(document).encode()
        response.__enter__.return_value = response
        opener = mock.Mock()
        opener.open.return_value = response
        return opener

    def test_private_metadata_is_bound_to_fixed_package_owner_and_type(self) -> None:
        good = {
            "name": registry.PACKAGE,
            "visibility": "private",
            "package_type": "container",
            "owner": {"login": "ElevenID"},
        }
        opener = self.metadata(good)
        with mock.patch.object(
            registry.urllib.request, "build_opener", return_value=opener
        ):
            registry.require_private_package(TOKEN)
        request = opener.open.call_args.args[0]
        self.assertEqual(registry.PACKAGE_URL, request.full_url)
        self.assertEqual("Bearer " + TOKEN, request.get_header("Authorization"))
        for mutation in (
            {"visibility": "public"},
            {"visibility": "internal"},
            {"name": "other"},
            {"owner": {"login": "other"}},
            {"package_type": "npm"},
            {"repository": {"full_name": "ElevenID/public"}},
        ):
            with mock.patch.object(
                registry.urllib.request,
                "build_opener",
                return_value=self.metadata({**good, **mutation}),
            ):
                with self.assertRaises(registry.RegistryAccessError):
                    registry.require_private_package(TOKEN)

    def test_metadata_failure_is_not_mistaken_for_private_visibility(self) -> None:
        opener = mock.Mock()
        opener.open.side_effect = OSError("fixture failure")
        with mock.patch.object(
            registry.urllib.request, "build_opener", return_value=opener
        ):
            with self.assertRaisesRegex(registry.RegistryAccessError, "unavailable"):
                registry.require_private_package(TOKEN)
        with self.assertRaises(registry.RegistryAccessError):
            registry.require_private_package("invalid\nheader")
        self.assertIsNone(
            registry.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://other.invalid"
            )
        )

    def test_anonymous_token_success_network_error_or_ambiguous_failure_cannot_pass(
        self,
    ) -> None:
        for status, body, accepted in [
            (403, {"errors": [{"code": "DENIED"}]}, True),
            (401, {"errors": [{"code": "UNAUTHORIZED"}]}, True),
            (404, {"errors": [{"code": "DENIED"}]}, False),
            (503, {"errors": [{"code": "DENIED"}]}, False),
            (403, {"errors": []}, False),
        ]:
            opener = mock.Mock()
            opener.open.side_effect = registry.urllib.error.HTTPError(
                "https://ghcr.io/token",
                status,
                "fixture",
                {},
                io.BytesIO(json.dumps(body).encode()),
            )
            with mock.patch.object(
                registry.urllib.request, "build_opener", return_value=opener
            ):
                if accepted:
                    registry.require_anonymous_pull_denied()
                else:
                    with self.assertRaises(registry.RegistryAccessError):
                        registry.require_anonymous_pull_denied()
        for opener in (
            self.metadata({"token": "public-anonymous-token"}),
            mock.Mock(open=mock.Mock(side_effect=OSError("offline"))),
        ):
            with mock.patch.object(
                registry.urllib.request, "build_opener", return_value=opener
            ):
                with self.assertRaises(registry.RegistryAccessError):
                    registry.require_anonymous_pull_denied()

    def test_login_scope_and_cleanup_survive_pull_or_visibility_failure(self) -> None:
        for failure in (None, "pull", "visibility"):
            calls = []
            config = None

            def run(command, environment, **options):
                calls.append((command, dict(environment), options))
                self.assertNotIn(TOKEN, " ".join(command))
                self.assertNotIn("RUST_RUNTIME_PULL_TOKEN", environment)
                self.assertNotIn("GITHUB_TOKEN", environment)
                return b"", b""

            checks = (
                [None, registry.RegistryAccessError("visibility changed")]
                if failure == "visibility"
                else [None, None]
            )
            with (
                mock.patch.object(
                    registry, "require_anonymous_pull_denied", side_effect=checks
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "RUST_RUNTIME_PULL_TOKEN": TOKEN,
                        "GITHUB_TOKEN": "other-credential",
                    },
                ),
            ):
                try:
                    with registry.private_pull_environment(
                        docker="docker",
                        image=IMAGE,
                        token=TOKEN,
                        actor="author",
                        run_process=run,
                    ) as environment:
                        config = pathlib.Path(environment["DOCKER_CONFIG"])
                        self.assertTrue(config.is_dir())
                        if failure == "pull":
                            raise RuntimeError("controlled pull failed")
                except (RuntimeError, registry.RegistryAccessError):
                    self.assertIsNotNone(failure)
                else:
                    self.assertIsNone(failure)
            self.assertIsNotNone(config)
            self.assertFalse(config.exists())
            self.assertEqual(
                ["login", "logout"], [command[1] for command, _, _ in calls]
            )
            self.assertEqual(TOKEN.encode(), calls[0][2]["stdin_data"])


if __name__ == "__main__":
    unittest.main()
