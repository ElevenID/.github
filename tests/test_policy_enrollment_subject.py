"""Check the real enrollment subject, including executable-input fault controls."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUBJECT = Path(".github/feature-regression/behavior_subject.py")


class EnrollmentSubjectTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        shutil.copytree(ROOT / ".github/feature-regression", root / ".github/feature-regression")
        for relative in [
            "scripts/feature_regression_observation_runner.py",
            "scripts/rust_runtime_bundle.py",
            ".github/actions/open-source-audit/private_forks_policy.py",
        ]:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        return root

    def run_subject(self, root):
        # No inherited Python import paths or account credentials enter the
        # child; the production producer supplies its own fixed environment.
        environment = {key: os.environ[key] for key in ("PATH", "SystemRoot", "SYSTEMROOT") if key in os.environ}
        return subprocess.run([sys.executable, "-B", str(root / SUBJECT)], cwd=root,
                              env=environment, capture_output=True, timeout=15)

    def statuses(self, result):
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        self.assertEqual(b"", result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual("elevenid.behavior-subject-output/v2", document["schema"])
        identities = [(item["operation_id"], item["case_id"], item["dimension"]) for item in document["observations"]]
        self.assertEqual(len(identities), len(set(identities)))
        return {item["case_id"]: item["value"] for item in document["observations"] if item["dimension"] == "public_status"}

    def test_real_policy_runner_and_bundle_boundaries(self):
        result = self.run_subject(self.fixture())
        statuses = self.statuses(result)
        self.assertEqual(46, len(statuses))
        accepted = {name for name, status in statuses.items() if status == "accepted"}
        self.assertEqual({"public-workflow", "python-inputs", "python-no-rust-build", "subject-output", "bundle-valid",
                          "target-valid", "github-output-valid", "atomic-new", "observation-valid"}, accepted)
        self.assertEqual({
            "registry-invalid-credential", "registry-untrusted-context",
            "source-local-lock", "source-unpinned-git", "source-empty-grants",
            "source-duplicate-catalog-key", "source-unadmitted-candidate",
            "fetch-untrusted-context", "fetch-wrong-credential-host",
            "fetch-missing-private-credential",
        }, {name for name, status in statuses.items() if status == "not_present"})
        self.assertTrue(all(status in {"accepted", "rejected", "not_present"} for status in statuses.values()))
        self.assertNotIn(b"DIAGNOSTIC_SENTINEL_VALUE", result.stdout)

    def test_actual_production_owner_drift_changes_observations(self):
        root = self.fixture()
        before = self.statuses(self.run_subject(root))
        owner = root / ".github/actions/open-source-audit/private_forks_policy.py"
        with owner.open("ab") as stream:
            stream.write(b"\nworkflow_secret_findings = lambda *args, **kwargs: []\n")
        after = self.statuses(self.run_subject(root))
        self.assertEqual("rejected", before["fork-secret"])
        self.assertEqual("accepted", after["fork-secret"])
        self.assertNotEqual(before, after)

    def test_dependency_tampering_is_rejected_before_import(self):
        root = self.fixture()
        marker = root / "unreviewed-code-executed"
        owner = root / ".github/feature-regression/vendor/yaml/__init__.py"
        owner.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
        result = self.run_subject(root)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"dependency bytes changed", result.stderr)
        self.assertFalse(marker.exists())

    def test_manifest_replacement_cannot_rebind_dependency_bytes(self):
        root = self.fixture()
        path = root / ".github/feature-regression/vendor/pyyaml-source.json"
        record = json.loads(path.read_bytes())
        record["files"].clear()
        path.write_text(json.dumps(record), encoding="utf-8")
        result = self.run_subject(root)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"dependency manifest changed", result.stderr)

    def test_candidate_sibling_cannot_shadow_initial_standard_library_import(self):
        root = self.fixture()
        marker = root / "unreviewed-code-executed"
        (root / ".github/feature-regression/json.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
        self.statuses(self.run_subject(root))
        self.assertFalse(marker.exists())

    def test_dependency_and_production_cache_namespaces_are_closed(self):
        for relative, message in [
            (".github/feature-regression/vendor/json.py", b"dependency import namespace changed"),
            ("scripts/__pycache__/injected.pyc", b"production script import namespace changed"),
            (".github/actions/open-source-audit/__pycache__/injected.pyc", b"source policy import namespace changed"),
        ]:
            with self.subTest(relative=relative):
                root = self.fixture()
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"not an admitted input")
                result = self.run_subject(root)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
