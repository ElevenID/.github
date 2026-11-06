from __future__ import annotations

import copy
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / ".github/actions/open-source-audit"))
import audit  # noqa: E402
import private_forks_policy as policy  # noqa: E402


FIXTURES = json.loads((Path(__file__).parent / "fixtures/private_fork_workflows.json").read_text())


class PrivateForkPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fixture = copy.deepcopy(FIXTURES[0])
        self.document = self.fixture["document"]
        self.job = self.document["jobs"]["preflight"]
        self.check, self.fetch = self.job["steps"]
        (self.root / "LICENSE").write_text("test license\n")
        # Unit tests use local stand-ins for reviewed implementations. The real
        # four consumer trees are also audited as an integration validation.
        targets = sorted({step.get("with", {}).get("target", "")
                          for fixture in FIXTURES for job in fixture["document"]["jobs"].values()
                          for step in job["steps"]})
        files = {policy.HELPER: "reviewed helper enforces HTTPS host/path and event trust\n"}
        for path in {**policy.DOCKER_FILES, **policy.PRODUCT_FILES}:
            files[path] = "reviewed fixture for " + path + "\n"
        files["rust/services/Dockerfile.ci"] += "\n".join("FROM runtime AS " + target for target in targets if target)
        digests = {}
        for relative, content in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(policy, "HELPER_SHA256", digests[policy.HELPER]).start()
        mock.patch.dict(policy.DOCKER_FILES, {p: digests[p] for p in policy.DOCKER_FILES}, clear=True).start()
        mock.patch.dict(policy.PRODUCT_FILES, {p: digests[p] for p in policy.PRODUCT_FILES}, clear=True).start()

    def findings(self, document=None, repository=None):
        return policy.workflow_secret_findings(
            self.root, policy.yaml.safe_dump(document or self.document, sort_keys=False),
            repository or self.fixture["repository"],
        )

    def reject(self, text):
        self.assertIn(text, "\n".join(self.findings()))

    def docker_fixture(self):
        self.fixture = copy.deepcopy(next(f for f in FIXTURES if f["workflow"] == "cd.yml"))
        self.document = self.fixture["document"]
        self.job = self.document["jobs"]["build-services"]
        self.check, self.fetch, _ = self.job["steps"]

    def test_actual_reviewed_step_patterns_from_all_four_consumers(self):
        self.assertEqual({f["repository"] for f in FIXTURES}, policy.REPOSITORIES)
        for fixture in FIXTURES:
            with self.subTest(repository=fixture["repository"], workflow=fixture["workflow"]):
                self.assertEqual([], self.findings(fixture["document"], fixture["repository"]))

    def test_secret_in_compile_or_test_is_rejected(self):
        for command in ("cargo test --locked", "cargo build --locked", "python tests.py"):
            with self.subTest(command=command):
                self.fetch["run"] = command
                self.assertTrue(self.findings())

    def test_shell_suffix_cannot_run_after_fetch_with_reader(self):
        self.fetch["run"] += "\ncargo test --locked"
        self.reject("invalid fetch arguments")

    def test_missing_or_reordered_trust_check_is_rejected(self):
        self.job["steps"] = [self.fetch, self.check]
        self.reject("lacks a prior credential-free trust check")
        self.job["steps"] = [self.fetch]
        self.reject("lacks a prior credential-free trust check")

    def test_conditional_away_or_narrower_trust_check_is_rejected(self):
        self.check["if"] = "false"
        self.reject("unreviewed condition")
        self.check["if"] = policy.NATIVE
        self.reject("lacks a prior credential-free trust check")

    def test_ignored_trust_failure_is_rejected(self):
        self.check["continue-on-error"] = True
        self.reject("ignores failure")

    def test_reader_cannot_bypass_failed_prior_steps(self):
        for status in ("always()", "failure()", "success() || failure()"):
            with self.subTest(status=status):
                self.fetch["if"] = status + " && " + policy.FLAG
                self.reject("overrides normal success ordering")

    def test_trust_check_receives_no_reader(self):
        self.check["env"] = {policy.TOKEN: policy.DIRECT}
        self.assertTrue(self.findings())

    def test_arbitrary_trust_command_tail_is_rejected(self):
        self.check["run"] += "\ntrue"
        self.assertTrue(self.findings())

    def test_other_secrets_remain_prohibited_in_pr_workflows(self):
        for expression in ("${{ secrets.OTHER_SECRET }}", "${{ secrets['OTHER_SECRET'] }}", "${{ toJSON(secrets) }}", "${{ true && secrets.OTHER_SECRET || '' }}"):
            with self.subTest(expression=expression):
                self.fetch["env"] = {"OTHER_SECRET": expression}
                self.reject("repository secret is outside the reviewed source-fetch step")
        self.document["jobs"] = {"test": {"steps": [self.fetch]}}
        self.reject("fork workflow references repository secrets")

    def test_unknown_repository_is_rejected(self):
        self.assertIn("not approved", "\n".join(self.findings(repository="Someone/marty-core")))

    def test_global_or_job_reader_binding_is_rejected_even_without_secret_syntax(self):
        for scope in (self.document, self.job):
            with self.subTest(scope=scope is self.job):
                scope["env"] = {policy.TOKEN: "${{ vars.reader }}"}
                self.reject("workflow/job environment variable")
                scope.pop("env")

    def test_trusted_runner_context_cannot_be_overridden(self):
        for scope in (self.document, self.job, self.check, self.fetch):
            saved = copy.deepcopy(scope.get("env"))
            scope.setdefault("env", {})["GITHUB_EVENT_PATH"] = "fake-event.json"
            self.assertTrue(self.findings())
            if saved is None:
                scope.pop("env")
            else:
                scope["env"] = saved

    def test_missing_changed_or_symlinked_helper_is_rejected(self):
        path = self.root / policy.HELPER
        path.write_text("changed runtime event/host/path policy\n")
        self.reject("reviewed file changed")
        path.unlink()
        self.reject("reviewed file missing")
        path.symlink_to(self.root / "LICENSE")
        self.reject("reviewed file missing")

    def test_helper_host_path_or_external_dependabot_rule_change_requires_review(self):
        path = self.root / policy.HELPER
        original = path.read_text()
        for mutation in ("allow github.example", "allow another/repo", "allow external PR", "allow Dependabot"):
            with self.subTest(mutation=mutation):
                path.write_text(original + mutation)
                self.reject("reviewed file changed")

    def test_arbitrary_manifest_host_path_or_shell_is_rejected(self):
        for path in ("https://github.example/repo/Cargo.toml", "../../Cargo.toml", "Cargo.toml;echo", "$(whoami)/Cargo.toml"):
            with self.subTest(path=path):
                self.fetch["run"] = "python .github/scripts/private-forks.py fetch --manifest-path " + path
                self.assertTrue(self.findings())

    def test_unsupported_event_and_pull_request_target_are_rejected(self):
        for event in ("workflow_run", "pull_request_target", "issue_comment"):
            self.document["on"] = {event: {}}
            self.reject("unsupported workflow event")

    def test_reader_in_non_step_scope_is_rejected(self):
        self.document["name"] = policy.DIRECT
        self.reject("outside the reviewed source-fetch step")

    def test_non_pr_unrelated_existing_secrets_are_unchanged(self):
        document = {"on": {"workflow_dispatch": {}}, "jobs": {"release": {"env": {"API_TOKEN": "${{ secrets.API_TOKEN }}"}}}}
        self.assertEqual([], self.findings(document))

    def test_duplicate_yaml_mapping_is_rejected(self):
        result = policy.workflow_secret_findings(self.root, "on: [pull_request]\non: [push]\njobs: {}\n", self.fixture["repository"])
        self.assertIn("duplicate", "\n".join(result))

    def test_malformed_yaml_diagnostic_does_not_return_source_content(self):
        source = "on: [pull_request]\nname: [DIAGNOSTIC_SENTINEL_VALUE\n"
        result = policy.workflow_secret_findings(self.root, source, self.fixture["repository"])
        self.assertEqual(["workflow YAML could not be parsed"], result)
        self.assertNotIn("DIAGNOSTIC_SENTINEL_VALUE", str(result))

    def test_cli_rejects_tree_without_logging_finding_content(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(audit, "audit", return_value=["rejected: DIAGNOSTIC_SENTINEL_VALUE"]), \
                mock.patch.object(sys, "argv", ["audit.py", "--repo-root", str(self.root)]), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(1, audit.main())
        self.assertEqual("Open-source policy audit failed. Repository policy validation rejected the current tree.\n", output.getvalue())
        self.assertEqual("", errors.getvalue())

    def test_docker_argument_instead_of_secret_mount_is_rejected(self):
        self.docker_fixture()
        self.fetch["with"]["build-args"] += "\nPRIVATE_FORKS_READ_TOKEN=${{ secrets.PRIVATE_FORKS_READ_TOKEN }}"
        self.assertTrue(self.findings())

    def test_conflicting_private_mode_argument_is_rejected(self):
        self.docker_fixture()
        self.fetch["with"]["build-args"] += "\nPRIVATE_FORKS_ENABLED=false"
        self.reject("one argument matching reader activation")

    def test_docker_secret_mount_cannot_be_removed_or_rebound(self):
        self.docker_fixture()
        self.fetch["with"]["secret-envs"] = "compile_token=PRIVATE_FORKS_READ_TOKEN"
        self.reject("missing dedicated fetch secret")

    def test_docker_recipe_change_requires_review(self):
        self.docker_fixture()
        (self.root / "services/Dockerfile").write_text("RUN --mount=type=secret,id=private_forks_read_token cargo test\n")
        self.reject("reviewed file changed")

    def test_docker_cache_or_build_record_exports_are_rejected(self):
        self.docker_fixture()
        for key in ("cache-from", "cache-to"):
            previous = self.fetch["with"].get(key)
            self.fetch["with"][key] = "type=gha,mode=max"
            self.reject("cache export/import is prohibited")
            if previous is None:
                self.fetch["with"].pop(key)
            else:
                self.fetch["with"][key] = previous
        self.fetch["env"]["DOCKER_BUILD_RECORD_UPLOAD"] = "true"
        self.reject("records must not be exported")

    def test_intermediate_docker_target_is_rejected(self):
        self.docker_fixture()
        self.fetch["with"]["target"] = "rust-service-builder"
        self.reject("intermediate source stage")

    def test_other_action_or_dockerfile_is_rejected(self):
        self.docker_fixture()
        self.fetch["uses"] = "someone/action@" + "a" * 40
        self.reject("unreviewed reader action")
        self.fetch["uses"] = policy.BUILD_ACTION
        self.fetch["with"]["file"] = "other/Dockerfile"
        self.reject("unreviewed Docker context or recipe")

    def test_indirect_reader_environment_cannot_reach_action_outputs(self):
        self.docker_fixture()
        for expression in ("${{ env.PRIVATE_FORKS_READ_TOKEN }}", "${{ env['PRIVATE_FORKS_READ_TOKEN'] }}", "${{ toJSON(env) }}", "${{ env.SERVICES_IMAGE }}"):
            with self.subTest(expression=expression):
                self.fetch["with"]["labels"] = expression
                self.reject("reader environment must not be disclosed")
        self.fetch["with"].pop("labels")
        self.fetch["name"] = "${{ toJSON(env) }}"
        self.reject("reader environment must not be disclosed")

    def test_product_token_condition_cannot_include_non_native_rows(self):
        fixture = copy.deepcopy(next(f for f in FIXTURES if f["workflow"] == "nightly-release.yml"))
        step = fixture["document"]["jobs"]["build-images"]["steps"][-1]
        step["with"]["private-forks-read-token"] = policy.CONDITIONAL
        self.assertIn("limited to enabled native rows", "\n".join(self.findings(fixture["document"], fixture["repository"])))

    def test_original_license_markers_runner_and_action_pinning_rules_remain(self):
        workflow = self.root / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("on:\n  pull_request_target:\n  pull_request:\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - uses: actions/checkout@main\n")
        marker = self.root / "billing.py"
        marker.write_text("PRODUCT_" + "CATALOG_TOKEN")
        (self.root / "LICENSE").unlink()
        with mock.patch.object(audit, "tracked_files", return_value=[workflow, marker]):
            result = "\n".join(audit.audit(self.root, self.fixture["repository"]))
        for message in ("missing repository license", "private marker", "not pinned", "pull_request_target", "self-hosted"):
            self.assertIn(message, result)


if __name__ == "__main__":
    unittest.main()
