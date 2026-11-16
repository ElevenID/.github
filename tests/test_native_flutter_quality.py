from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
