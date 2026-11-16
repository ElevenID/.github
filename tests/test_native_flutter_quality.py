from __future__ import annotations

import hashlib
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / ".github/actions/open-source-audit"))
import private_forks_policy as policy  # noqa: E402


ROOT = Path(__file__).parents[1]
PROFILE = ".github/workflows/quality-flutter.yml"


class NativeFlutterQualityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = (ROOT / PROFILE).read_text(encoding="utf-8")
        self.path = self.root / PROFILE
        self.path.parent.mkdir(parents=True)

    def findings(self, source=None, repository="ElevenID/.github", path=PROFILE):
        source = self.source if source is None else source
        self.path.write_bytes(source.encode("utf-8"))
        return policy.workflow_secret_findings(
            self.root, source, repository, workflow_path=path
        )

    def test_exact_reviewed_definition_and_crlf_are_accepted(self):
        self.assertEqual(hashlib.sha256(self.source.encode()).hexdigest(), policy.NATIVE_FLUTTER_DEFINITION_SHA256)
        self.assertEqual(self.findings(), [])
        self.assertEqual(self.findings(self.source.replace("\n", "\r\n")), [])

    def test_unreviewed_bytes_or_scope_changes_are_rejected(self):
        for changed in (
            self.source + "\n# unreviewed\n",
            self.source.replace('test "$GITHUB_REPOSITORY" = "ElevenID/marty-authenticator"', "true"),
            self.source.replace('test "$NATIVE_WORKING_DIRECTORY" = "."', "true"),
            self.source.replace("rust/Cargo.toml", "other/Cargo.toml"),
        ):
            with self.subTest(change=hashlib.sha256(changed.encode()).hexdigest()):
                self.assertTrue(self.findings(changed))

    def test_reader_relocation_or_other_secret_is_rejected(self):
        self.assertTrue(self.findings(self.source.replace(
            "PRIVATE_FORKS_READ_TOKEN: ${{ secrets.PRIVATE_FORKS_READ_TOKEN }}",
            "PRIVATE_FORKS_READ_TOKEN: ${{ secrets.ADMIN_TOKEN }}",
        )))
        self.assertTrue(self.findings(self.source.replace(
            "permissions:\n  contents: read", "env:\n  PRIVATE_FORKS_READ_TOKEN: ${{ secrets.PRIVATE_FORKS_READ_TOKEN }}\npermissions:\n  contents: read",
        )))

    def test_definition_is_not_portable_to_other_repositories_or_paths(self):
        self.assertTrue(self.findings(repository="ElevenID/marty-authenticator"))
        self.assertTrue(self.findings(path=".github/workflows/other.yml"))
        self.assertTrue(policy.workflow_secret_findings(self.root, self.source, "ElevenID/.github"))

    def test_native_mode_is_opt_in_and_has_one_scoped_fetch_reader(self):
        document = policy.yaml.load(self.source, Loader=policy.WorkflowLoader)
        call = document["on"]["workflow_call"]
        self.assertEqual(call["inputs"]["native-rust-bridge"]["type"], "boolean")
        self.assertEqual(call["inputs"]["native-rust-bridge"]["default"], "false")
        self.assertEqual(call["secrets"][policy.TOKEN]["required"], "false")
        job = document["jobs"]["flutter-quality"]
        steps = job["steps"]
        fetch = next(step for step in steps if step.get("name") == "Fetch locked native fork dependencies")
        check = next(step for step in steps if step.get("name") == "Require trusted native fork access")
        self.assertEqual(fetch["env"], {policy.TOKEN: policy.DIRECT})
        self.assertEqual(fetch["if"], check["if"])
        self.assertLess(steps.index(check), steps.index(fetch))
        self.assertEqual(fetch["run"], "python .github/scripts/private-forks.py fetch --manifest-path rust/Cargo.toml")
        self.assertEqual(len(policy.secret_values(document)), 1)
        self.assertNotIn(policy.TOKEN, document.get("env", {}))
        self.assertNotIn(policy.TOKEN, job.get("env", {}))


class NativeFlutterCallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        helper = self.root / policy.HELPER
        helper.parent.mkdir(parents=True)
        # Structural policy fixture only; the real helper is checked separately
        # in consumer-source auditing and by the pinned callee at runtime.
        helper.write_bytes(b"reviewed runtime helper fixture\n")
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(policy.ADDITIONAL_HELPER_SHA256, {
            "ElevenID/marty-authenticator": hashlib.sha256(helper.read_bytes()).hexdigest(),
        }).start()
        self.job = {
            "uses": policy.NATIVE_FLUTTER_CALLEE,
            "with": copy.deepcopy(policy.NATIVE_FLUTTER_INPUTS),
            "secrets": {policy.TOKEN: policy.DIRECT},
        }
        self.document = {
            "on": {"pull_request": {"branches": ["main"]}, "push": {"branches": ["main"]}, "workflow_dispatch": {}},
            "jobs": {"flutter-quality": self.job},
        }

    def findings(self, repository="ElevenID/marty-authenticator", path=policy.NATIVE_FLUTTER_CALLER):
        return policy.workflow_secret_findings(
            self.root, policy.yaml.safe_dump(self.document), repository, workflow_path=path
        )

    def test_exact_pinned_caller_is_accepted(self):
        self.assertEqual(self.findings(), [])
        self.assertTrue(policy.NATIVE_FLUTTER_CALLEE.endswith("@bf660ca444c40b260b413d599f6504d4324227e8"))

    def test_other_repository_path_or_job_cannot_delegate(self):
        for repository, path in (
            ("ElevenID/marty-ui", policy.NATIVE_FLUTTER_CALLER),
            ("ElevenID/marty-authenticator", ".github/workflows/other.yml"),
            ("ElevenID/marty-authenticator", None),
        ):
            with self.subTest(repository=repository, path=path):
                self.assertTrue(self.findings(repository, path))
        self.document["jobs"]["other"] = self.document["jobs"].pop("flutter-quality")
        self.assertTrue(self.findings())

    def test_mutable_other_or_unmerged_callee_is_rejected(self):
        for ref in ("main", "022aa01bd7315f230563531cfe9812cd5a800a45", "0" * 40):
            with self.subTest(ref=ref):
                self.job["uses"] = policy.NATIVE_FLUTTER_CALLEE.split("@")[0] + "@" + ref
                self.assertTrue(self.findings())
        self.job["uses"] = "other/org/.github/workflows/quality-flutter.yml@bf660ca444c40b260b413d599f6504d4324227e8"
        self.assertTrue(self.findings())

    def test_input_commands_paths_and_native_mode_are_fixed(self):
        for key, value in (
            ("build-command", "printenv"), ("test-command", "true"),
            ("working-directory", "other"), ("native-rust-bridge", "false"),
            ("flutter-version", "stable"), ("extra", "unreviewed"),
        ):
            with self.subTest(key=key):
                self.job["with"] = {**policy.NATIVE_FLUTTER_INPUTS, key: value}
                self.assertTrue(self.findings())
        self.job["with"] = dict(policy.NATIVE_FLUTTER_INPUTS)
        del self.job["with"]["working-directory"]
        self.assertTrue(self.findings())

    def test_inheritance_other_secrets_and_job_context_are_rejected(self):
        for secrets in ("inherit", {policy.TOKEN: policy.DIRECT, "ADMIN": "${{ secrets.ADMIN }}"}, {policy.TOKEN: "${{ secrets.ADMIN }}"}):
            with self.subTest(secrets=secrets):
                self.job["secrets"] = secrets
                self.assertTrue(self.findings())
        self.job["secrets"] = {policy.TOKEN: policy.DIRECT}
        self.job["env"] = {"GITHUB_REF": "refs/heads/main"}
        self.assertTrue(self.findings())

    def test_helper_change_and_other_token_placement_remain_rejected(self):
        helper = self.root / policy.HELPER
        original = helper.read_bytes()
        helper.write_bytes(original + b"changed")
        self.assertTrue(self.findings())
        helper.write_bytes(original)
        self.document["jobs"]["unreviewed"] = {"runs-on": "ubuntu-latest", "env": {"LEAK": policy.DIRECT}}
        self.assertTrue(self.findings())


if __name__ == "__main__":
    unittest.main()
