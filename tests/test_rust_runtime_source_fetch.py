from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

import yaml

from scripts import rust_runtime_source_fetch as fetcher


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SourceFetchTests(unittest.TestCase):
    def context(self):
        return {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "ElevenID/.github",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": fetcher.WORKFLOW_REF,
            "GITHUB_SHA": "a" * 40,
            "GITHUB_ACTOR": "operator",
        }

    def test_only_main_dispatch_in_exact_publisher_can_fetch(self):
        event = {"repository": {"full_name": "ElevenID/.github"}}
        fetcher.require_context(self.context(), event)
        for key, value in {
            "GITHUB_ACTIONS": "false",
            "GITHUB_REPOSITORY": "someone/.github",
            "GITHUB_REF": "refs/heads/feature",
            "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_WORKFLOW_REF": fetcher.WORKFLOW_REF.replace("main", "feature"),
            "GITHUB_SHA": "main",
            "GITHUB_ACTOR": "",
            "GITHUB_TRIGGERING_ACTOR": "dependabot[bot]",
        }.items():
            with self.subTest(key=key), self.assertRaises(fetcher.FetchError):
                fetcher.require_context({**self.context(), key: value}, event)
        with self.assertRaises(fetcher.FetchError):
            fetcher.require_context(
                self.context(), {"repository": {"full_name": "fork/.github"}}
            )

    def test_credentials_are_scoped_to_only_three_https_git_paths(self):
        environment = {fetcher.TOKEN: "fake-test-token"}
        for path in fetcher.PRIVATE_FORKS:
            response = fetcher.credential_response(
                "get",
                f"protocol=https\nhost=github.com\npath={path}.git\n",
                environment,
            )
            self.assertIn("password=fake-test-token", response)
        for request in (
            "protocol=http\nhost=github.com\npath=ElevenID/ssi-elevenid",
            "protocol=https\nhost=github.com.evil\npath=ElevenID/ssi-elevenid",
            "protocol=https\nhost=github.com\npath=ElevenID/unreviewed",
            "protocol=https\nhost=github.com\npath=ElevenID/ssi-elevenid/../other",
            "protocol=https\nhost=github.com\npath=ElevenID/ssi-elevenid\nhost=evil",
        ):
            self.assertEqual(
                "", fetcher.credential_response("get", request, environment)
            )
        self.assertEqual("", fetcher.credential_response("store", "", environment))
        self.assertEqual("", fetcher.credential_response("erase", "", environment))

    def test_fetch_environment_replaces_config_and_redirect_hooks(self):
        with mock.patch.dict(
            os.environ,
            {
                "CARGO_BUILD_RUSTC": "evil",
                "GIT_CONFIG_COUNT": "99",
                "GIT_CONFIG_VALUE_90": "evil",
                "RUSTFLAGS": "evil",
                "LD_PRELOAD": "evil",
            },
            clear=True,
        ):
            environment = fetcher.fetch_environment(pathlib.Path("cache"))
        for name in (
            "CARGO_BUILD_RUSTC",
            "GIT_CONFIG_VALUE_90",
            "RUSTFLAGS",
            "LD_PRELOAD",
        ):
            self.assertNotIn(name, environment)
        config = {
            environment[f"GIT_CONFIG_KEY_{n}"]: environment[f"GIT_CONFIG_VALUE_{n}"]
            for n in range(int(environment["GIT_CONFIG_COUNT"]))
        }
        self.assertEqual("false", config["http.followRedirects"])
        self.assertEqual("true", config["credential.useHttpPath"])
        self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
        self.assertEqual("/dev/null", config["core.hooksPath"])

    def test_fetch_never_compiles_and_removes_token_after_failure(self):
        original = pathlib.Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            def process(argv, environment, **kwargs):
                self.assertEqual(["fetch", "--locked", "--manifest-path"], argv[1:4])
                self.assertTrue(pathlib.Path(argv[4]).is_absolute())
                self.assertFalse(pathlib.Path.cwd().is_relative_to(root))
                self.assertEqual("fake-test-token", environment[fetcher.TOKEN])
                raise RuntimeError("private diagnostics must not escape the CLI")

            with (
                mock.patch.object(
                    fetcher,
                    "checked_bundle",
                    return_value={"manifest_path": "probe/Cargo.toml"},
                ),
                mock.patch.object(fetcher.shutil, "which", return_value="cargo"),
                mock.patch.object(fetcher, "_run_process", side_effect=process),
                mock.patch.dict(os.environ, {fetcher.TOKEN: "fake-test-token"}),
            ):
                with self.assertRaises(RuntimeError):
                    fetcher.fetch(root, "reviewed")
                self.assertNotIn(fetcher.TOKEN, os.environ)
            self.assertEqual(original, pathlib.Path.cwd())

    def test_fresh_cache_and_persisted_credentials_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with (
                mock.patch.object(
                    fetcher,
                    "checked_bundle",
                    return_value={"manifest_path": "probe/Cargo.toml"},
                ),
                mock.patch.object(fetcher.shutil, "which", return_value="cargo"),
                mock.patch.dict(os.environ, {fetcher.TOKEN: "fake-test-token"}),
            ):
                (root / fetcher.CACHE).mkdir()
                with self.assertRaisesRegex(fetcher.FetchError, "fresh"):
                    fetcher.fetch(root, "reviewed")

    def test_workflow_keeps_source_token_out_of_build_and_raw_evidence_private(self):
        path = ROOT / ".github/workflows/publish-restricted-rust-probe-runtime.yml"
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["publish"]["steps"]
        token_steps = [
            step for step in steps if "secrets.PRIVATE_FORKS_READ_TOKEN" in str(step)
        ]
        self.assertEqual(1, len(token_steps))
        self.assertIn("source_fetch.py fetch", token_steps[0]["run"])
        uploads = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        ]
        self.assertEqual(
            ["${{ runner.temp }}/rust-runtime-public-receipt"],
            [step["with"]["path"] for step in uploads],
        )
        evidence = next(step for step in steps if step.get("id") == "evidence")["run"]
        self.assertIn("docker create", evidence)
        self.assertIn("docker cp", evidence)
        self.assertNotIn("docker start", evidence)
        self.assertNotIn("docker run", evidence)
        self.assertIn("cmp ", evidence)
        recipe = (ROOT / "runtime/rust-cargo/Dockerfile.restricted").read_text(
            encoding="utf-8"
        )
        self.assertIn("RUN --network=none", recipe)
        self.assertIn("cargo vendor --frozen --offline", recipe)
        self.assertNotIn("--mount=type=secret", recipe)
        self.assertNotIn("PRIVATE_FORKS_READ_TOKEN", recipe)


if __name__ == "__main__":
    unittest.main()
