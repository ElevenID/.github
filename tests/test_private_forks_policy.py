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
CODEQL_CASES = (
    (0, "preflight", "vars.PRIVATE_FORKS_ENABLED == 'true' && matrix.language == 'rust'"),
    (1, "test-rust-services", "vars.PRIVATE_FORKS_ENABLED == 'true' && steps.scope.outputs.analyze == 'true' && steps.test_only.outputs.skip != 'true'"),
)


class RestrictedPublisherPolicyTests(unittest.TestCase):
    def test_exact_publisher_and_transitive_closure_are_required(self):
        source = Path(__file__).resolve().parents[1]
        content = (source / policy.RESTRICTED_PUBLISHER).read_text(encoding="utf-8")
        def findings(root, text=content, repository="ElevenID/.github", workflow_path=policy.RESTRICTED_PUBLISHER):
            return policy.workflow_secret_findings(root, text, repository, workflow_path=workflow_path)
        self.assertEqual([], findings(source))
        self.assertTrue(findings(source, repository="ElevenID/marty-ui"))
        self.assertTrue(findings(source, workflow_path=".github/workflows/other.yml"))
        self.assertTrue(findings(source, text=content + "\n# changed workflow\n"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in policy.RESTRICTED_PUBLISHER_FILES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text((source / relative).read_text(encoding="utf-8"), encoding="utf-8")
            for name in policy.RESTRICTED_SCRIPT_NAMES:
                target = root / "scripts" / name
                if not target.exists():
                    target.write_text("# unused sibling\n", encoding="utf-8")
            self.assertEqual([], findings(root))
            for relative in policy.RESTRICTED_PUBLISHER_FILES:
                with self.subTest(relative=relative):
                    target = root / relative
                    original = target.read_bytes()
                    target.write_bytes(original + b"\n# unreviewed\n")
                    self.assertTrue(findings(root))
                    target.write_bytes(original)
            for name in ("json.py", "__init__.py"):
                target = root / "scripts" / name
                target.write_text("# import injection\n", encoding="utf-8")
                self.assertTrue(findings(root))
                target.unlink()


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
        # six consumer trees are also audited as an integration validation.
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
        mock.patch.dict(policy.ADDITIONAL_HELPER_SHA256, {
            repository: digests[policy.HELPER]
            for repository in policy.ADDITIONAL_HELPER_SHA256
        }, clear=True).start()
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

    def test_managed_postgres_context_only_excludes_two_additional_test_sources(self):
        self.docker_fixture()
        fixture = Path(__file__).parent / "fixtures/marty-ui-provider-neutral-services-Dockerfile.migrations.dockerignore"
        previous = fixture.read_bytes()
        anchor = b"rust/crates/selfhost-acceptance/tests/native_kms_schema_contract.rs\n"
        extra = (b"rust/crates/selfhost-acceptance/tests/managed_postgres_contract.rs\n"
                 b"rust/crates/selfhost-acceptance/tests/support/managed_postgres.rs\n")
        self.assertEqual(previous.count(anchor), 1)
        candidate = previous.replace(anchor, anchor + extra)
        path = self.root / "services/Dockerfile.migrations.dockerignore"
        path.write_bytes(candidate)
        self.assertEqual([], self.findings())
        path.write_bytes(candidate + b"!**/.cargo\n")
        self.reject("reviewed file changed: services/Dockerfile.migrations.dockerignore")

    def test_exact_delegated_use_runtime_copy_preserves_previous_recipe(self):
        self.docker_fixture()
        fixture = Path(__file__).parent / "fixtures/marty-ui-provider-neutral.Dockerfile"
        original = fixture.read_bytes()
        anchor = b"COPY --from=rust-service-builder /build/rust/target/release/marty-signing-keys /usr/local/bin/marty-signing-keys\n"
        self.assertEqual(original.count(anchor), 1)
        candidate = original.replace(anchor, anchor + anchor.replace(b"marty-signing-keys", b"marty-delegated-use"))
        path = self.root / "services/Dockerfile"
        for reviewed in (original, candidate):
            path.write_bytes(reviewed)
            self.assertEqual([], self.findings())
        path.write_bytes(candidate + b"COPY . /app\n")
        self.reject("reviewed file changed: services/Dockerfile")

    def test_exact_delegated_owner_migration_recipe_and_contract_inputs(self):
        self.docker_fixture()
        fixtures = Path(__file__).parent / "fixtures"
        recipe = (fixtures / "marty-ui-provider-neutral-migration.Dockerfile").read_bytes()
        context = (fixtures / "marty-ui-provider-neutral-services-Dockerfile.migrations.dockerignore").read_bytes()
        contracts = (
            b"http-charset-headers-oracle.json", b"http-euc-kr-codec.json",
            b"http-gb18030-codec.json", b"http-single-byte-codecs.json",
            b"http-unicode-text-oracle.json", b"organization-permission-catalog.json",
        )
        folders = (b"http-iso2022-codecs", b"http-multibyte-codecs")
        recipe_anchor = b"COPY contracts/issuer-identity-inspection-response.json /build/contracts/issuer-identity-inspection-response.json\n"
        recipe = recipe.replace(recipe_anchor, recipe_anchor
            + b"COPY " + b" ".join(b"contracts/" + name for name in contracts) + b" /build/contracts/\n"
            + b"".join(b"COPY contracts/" + name + b" /build/contracts/" + name + b"\n" for name in folders))
        command = b"marty-delegated-use-migrate"
        recipe = recipe.replace(
            b"--bin marty-demo-vendor-seed\n",
            b"--bin marty-demo-vendor-seed \\\n    && cargo build --locked --release -p marty-delegated-use --bin " + command + b"\n",
        )
        copy_seed = b"COPY --from=rust-migration-builder /build/rust/target/release/marty-demo-vendor-seed /usr/local/bin/marty-demo-vendor-seed\n"
        recipe = recipe.replace(copy_seed, copy_seed + copy_seed.replace(b"marty-demo-vendor-seed", command))
        managed_anchor = b"rust/crates/selfhost-acceptance/tests/native_kms_schema_contract.rs\n"
        context = context.replace(managed_anchor, managed_anchor
            + b"rust/crates/selfhost-acceptance/tests/managed_postgres_contract.rs\n"
            + b"rust/crates/selfhost-acceptance/tests/support/managed_postgres.rs\n")
        context_anchor = b"!contracts/issuer-identity-inspection-response.json\n"
        context = context.replace(context_anchor, context_anchor
            + b"".join(b"!contracts/" + name + b"\n" for name in contracts)
            + b"".join(b"!contracts/" + name + b"/\n!contracts/" + name + b"/*.json\n" for name in folders))
        for path, candidate, broadening in (
            ("services/Dockerfile.migrations", recipe, b"COPY . /app\n"),
            ("services/Dockerfile.migrations.dockerignore", context, b"!contracts/**\n"),
        ):
            (self.root / path).write_bytes(candidate)
            self.assertEqual([], self.findings())
            (self.root / path).write_bytes(candidate + broadening)
            self.reject("reviewed file changed: " + path)
            (self.root / path).write_bytes(candidate)

    def test_reviewed_public_demo_context_is_accepted_without_replacing_old_context(self):
        self.docker_fixture()
        self.assertEqual([], self.findings())
        path = self.root / "services/Dockerfile.migrations.dockerignore"
        approved = (Path(__file__).parent / "fixtures/marty-ui-public-demo-migrations.dockerignore").read_bytes()
        self.assertEqual(hashlib.sha256(approved).hexdigest(), "49c4641b787b3fa7a1b57af9f39e588625b424da5945c92f3f4523894c9ddc2f")
        path.write_bytes(approved)
        self.assertEqual([], self.findings())
        for changed in (approved + b"\n", approved.replace(b"rust/crates/flow-acceptance/tests/public_demo_signing_live_kms.rs\n", b""), b"**\n"):
            with self.subTest(changed_digest=hashlib.sha256(changed).hexdigest()):
                path.write_bytes(changed)
                self.reject("reviewed file changed: services/Dockerfile.migrations.dockerignore")

    def test_provider_neutral_service_image_removes_only_the_reviewed_binaries(self):
        self.docker_fixture()
        path = self.root / "services/Dockerfile"
        approved = (Path(__file__).parent / "fixtures/marty-ui-provider-neutral.Dockerfile").read_bytes()
        self.assertEqual(hashlib.sha256(approved).hexdigest(), "4274f3ef5c7661d11899aa0ed033d8c07b5daf6ca48164412aaca1eaaa1355dd")
        anchor = b"COPY --from=rust-service-builder /build/rust/target/release/marty-passport-beta-bureau /usr/local/bin/marty-passport-beta-bureau\n"
        removed = (b"COPY --from=rust-service-builder /build/rust/target/release/marty-canvas-sync-worker /usr/local/bin/marty-canvas-sync-worker\n"
                   b"COPY --from=rust-service-builder /build/rust/target/release/marty-canvas-sandbox /usr/local/bin/marty-canvas-sandbox\n")
        self.assertEqual(approved.count(anchor), 1)
        self.assertEqual(hashlib.sha256(approved.replace(anchor, removed + anchor)).hexdigest(),
                         "39a407063f7cbf89eb23c4d7121db3df69cfa826be1e2fb0e125733711e74362")
        self.assertEqual([], self.findings())  # Original approval remains valid.
        path.write_bytes(approved)
        self.assertEqual([], self.findings())
        for changed in (approved + b"\n", approved.replace(b"--mount=type=secret", b"--mount=type=bind")):
            with self.subTest(changed_digest=hashlib.sha256(changed).hexdigest()):
                self.assertNotEqual(changed, approved)
                path.write_bytes(changed)
                self.reject("reviewed file changed: services/Dockerfile")

    def test_provider_neutral_contexts_are_exact_and_path_bound(self):
        self.docker_fixture()
        fixtures = {'services/Dockerfile': ('marty-ui-provider-neutral.Dockerfile', '4274f3ef5c7661d11899aa0ed033d8c07b5daf6ca48164412aaca1eaaa1355dd'), 'rust/services/Dockerfile.ci': ('marty-ui-provider-neutral-rust-services-Dockerfile.ci', '7321a858f3e09c472ccd22d91ccc82dbf189f382eb3cbe05fc3a4650b436e137'), 'services/Dockerfile.dockerignore': ('marty-ui-provider-neutral-services-Dockerfile.dockerignore', 'affab88b0b8ad5c1ce4afe516c53d8288cc6cb52eba123744527632a4fad232a'), 'services/Dockerfile.migrations.dockerignore': ('marty-ui-provider-neutral-services-Dockerfile.migrations.dockerignore', 'a4657728c1cf90026a14268e8bf447e17c3caed8eb6d1406dc1ef4a359291e88'), 'rust/services/Dockerfile.ci.dockerignore': ('marty-ui-provider-neutral-rust-services-Dockerfile.ci.dockerignore', 'd5e6ec358829182d6be892c41e87335e9b0dce5cde37b69d29f88adb1454d8cd')}
        for relative, (fixture, digest) in fixtures.items():
            with self.subTest(path=relative):
                approved = (Path(__file__).parent / "fixtures" / fixture).read_bytes()
                self.assertEqual(hashlib.sha256(approved).hexdigest(), digest)
                path = self.root / relative
                previous = path.read_bytes()
                path.write_bytes(approved)
                self.assertEqual([], self.findings())
                path.write_bytes(approved + b"\n")
                self.reject("reviewed file changed: " + relative)
                path.write_bytes(previous)
                # A hash admitted at one path cannot authorize another reader file.
                wrong = self.root / ("services/Dockerfile.migrations" if relative != "services/Dockerfile.migrations"
                                     else "services/Dockerfile")
                original_wrong = wrong.read_bytes()
                wrong.write_bytes(approved)
                self.reject("reviewed file changed: " + str(wrong.relative_to(self.root)).replace("\\", "/"))
                wrong.write_bytes(original_wrong)

    def test_provider_neutral_migration_image_removes_only_the_retired_seed(self):
        self.docker_fixture()
        path = self.root / "services/Dockerfile.migrations"
        approved = (Path(__file__).parent / "fixtures/marty-ui-provider-neutral-migration.Dockerfile").read_bytes()
        self.assertEqual(hashlib.sha256(approved).hexdigest(), "3e7aa6d6c89b2cd93966b1eafd94930102ec2c55390d52cbe6d96c77abe93b4c")
        vendor_build = b"    && cargo build --locked --release -p marty-demo-vendor-seed --bin marty-demo-vendor-seed\n"
        retired_build = b"    && cargo build --locked --release -p marty-canvas-demo-seed --bin marty-canvas-demo-seed\n"
        vendor_copy = b"COPY --from=rust-migration-builder /build/rust/target/release/marty-demo-vendor-seed /usr/local/bin/marty-demo-vendor-seed\n"
        retired_copy = b"COPY --from=rust-migration-builder /build/rust/target/release/marty-canvas-demo-seed /usr/local/bin/marty-canvas-demo-seed\n"
        self.assertEqual(approved.count(vendor_build), 1)
        self.assertEqual(approved.count(vendor_copy), 1)
        previous = approved.replace(vendor_build, vendor_build[:-1] + b" \\\n" + retired_build)
        previous = previous.replace(vendor_copy, vendor_copy + retired_copy)
        self.assertEqual(hashlib.sha256(previous).hexdigest(), "66cd05d2153f018cf1637a5f4a73864ff73ea01550ea06cc10d670a7df7bbb3d")
        self.assertEqual([], self.findings())
        path.write_bytes(approved)
        self.assertEqual([], self.findings())
        for changed in (approved + b"\n", approved.replace(b"--mount=type=secret", b"--mount=type=bind")):
            path.write_bytes(changed)
            self.reject("reviewed file changed: services/Dockerfile.migrations")

    def test_migration_recipe_digest_cannot_authorize_another_reader_file(self):
        self.docker_fixture()
        approved = (Path(__file__).parent / "fixtures/marty-ui-provider-neutral-migration.Dockerfile").read_bytes()
        (self.root / "services/Dockerfile").write_bytes(approved)
        self.reject("reviewed file changed: services/Dockerfile")

    def test_provider_neutral_digest_cannot_authorize_another_reader_file(self):
        self.docker_fixture()
        approved = (Path(__file__).parent / "fixtures/marty-ui-provider-neutral.Dockerfile").read_bytes()
        (self.root / "services/Dockerfile.migrations").write_bytes(approved)
        self.reject("reviewed file changed: services/Dockerfile.migrations")

    def test_public_demo_context_digest_cannot_authorize_another_reader_file(self):
        self.docker_fixture()
        approved = (Path(__file__).parent / "fixtures/marty-ui-public-demo-migrations.dockerignore").read_bytes()
        (self.root / "services/Dockerfile.dockerignore").write_bytes(approved)
        self.reject("reviewed file changed: services/Dockerfile.dockerignore")

    def codeql_fixture(self, fixture_index, job_name, condition):
        self.fixture = copy.deepcopy(FIXTURES[fixture_index])
        self.document = self.fixture["document"]
        self.job = self.document["jobs"][job_name]
        self.check = next(step for step in self.job["steps"] if " check" in step.get("run", ""))
        self.fetch = next(step for step in self.job["steps"] if " fetch" in step.get("run", ""))
        self.job["steps"] = [self.check, self.fetch]
        self.document["jobs"] = {"analyze": self.job}
        self.check["if"] = self.fetch["if"] = condition

    def test_actual_reviewed_step_patterns_from_all_six_consumers(self):
        self.assertEqual({f["repository"] for f in FIXTURES}, policy.REPOSITORIES)
        for fixture in FIXTURES:
            with self.subTest(repository=fixture["repository"], workflow=fixture["workflow"]):
                self.assertEqual([], self.findings(fixture["document"], fixture["repository"]))

    def test_new_consumer_digest_cannot_change_the_original_consumer_boundary(self):
        helper = self.root / policy.HELPER
        original = helper.read_text()
        extended = original + "reviewed six-consumer allowlist\n"
        digest = hashlib.sha256(extended.encode()).hexdigest()
        helper.write_bytes(extended.encode())
        for repository in policy.ADDITIONAL_HELPER_SHA256:
            policy.ADDITIONAL_HELPER_SHA256[repository] = digest
        for fixture in FIXTURES:
            findings = self.findings(fixture["document"], fixture["repository"])
            if fixture["repository"] in policy.ADDITIONAL_HELPER_SHA256:
                self.assertEqual(findings, [])
            else:
                self.assertIn("reviewed file changed", "\n".join(findings))
        helper.write_text(original)
        for fixture in FIXTURES:
            findings = self.findings(fixture["document"], fixture["repository"])
            if fixture["repository"] in policy.ADDITIONAL_HELPER_SHA256:
                self.assertIn("reviewed file changed", "\n".join(findings))
            else:
                self.assertEqual(findings, [])

    def test_reviewed_wallet_context_is_exact_and_preserves_previous_approval(self):
        self.docker_fixture()
        path = self.root / "services/Dockerfile.migrations.dockerignore"
        previous = (Path(__file__).parent / "fixtures/marty-ui-public-demo-migrations.dockerignore").read_bytes()
        approved = (Path(__file__).parent / "fixtures/marty-ui-wallet-issuer-migrations.dockerignore").read_bytes()
        self.assertEqual(hashlib.sha256(approved).hexdigest(), "34b5595a059971b3f88aec033e2a421149ebfaf5219440914ec0212b526b19ee")
        anchor = b"rust/crates/service-acceptance/tests/holder_remote_live_kms.rs\n"
        added = (b"rust/crates/service-acceptance/tests/support/holder_issuer_authority.rs\n"
                 b"rust/crates/service-acceptance/tests/support/holder_native_receipt.rs\n")
        self.assertEqual(previous.count(anchor), 1)
        self.assertEqual(approved, previous.replace(anchor, anchor + added))
        self.assertEqual([], self.findings())
        for content in (previous, approved):
            path.write_bytes(content)
            self.assertEqual([], self.findings())
        for changed in (
            approved + b"\n",
            approved.replace(b"rust/crates/service-acceptance/tests/support/holder_native_receipt.rs\n", b""),
            approved.replace(b"rust/crates/service-acceptance/tests/support/holder_native_receipt.rs", b"rust/services/issuance/src/lib.rs"),
            b"**\n",
        ):
            with self.subTest(changed_digest=hashlib.sha256(changed).hexdigest()):
                path.write_bytes(changed)
                self.reject("reviewed file changed: services/Dockerfile.migrations.dockerignore")
        path.write_bytes(approved)
        (self.root / "services/Dockerfile.dockerignore").write_bytes(approved)
        self.reject("reviewed file changed: services/Dockerfile.dockerignore")

    def test_new_consumers_cannot_use_other_helper_paths_or_compile_with_the_reader(self):
        for fixture in FIXTURES:
            if fixture["repository"] not in policy.ADDITIONAL_HELPER_SHA256:
                continue
            for command in (
                "python other/private-forks.py fetch --manifest-path rust/Cargo.toml",
                "cargo test --locked --manifest-path rust/Cargo.toml",
            ):
                document = copy.deepcopy(fixture["document"])
                job = next(iter(document["jobs"].values()))
                job["steps"][-1]["run"] = command
                self.assertTrue(self.findings(document, fixture["repository"]))

    def test_codeql_conditions_accept_matching_or_broader_reviewed_check(self):
        for case in CODEQL_CASES:
            for check_condition in (case[2], policy.FLAG):
                with self.subTest(condition=case[2], check=check_condition):
                    self.codeql_fixture(*case)
                    self.check["if"] = check_condition
                    self.assertEqual([], self.findings())

    def test_codeql_conditions_do_not_admit_unreviewed_predicates(self):
        for case in CODEQL_CASES:
            condition = case[2]
            variants = (
                condition + " || true",
                condition.replace(policy.FLAG, "vars.PRIVATE_FORKS_ENABLED != 'true'"),
                condition.replace("matrix.language == 'rust'", "matrix.language == 'python'")
                if case[0] == 0 else condition.replace("steps.scope.outputs.analyze == 'true'", "steps.scope.outputs.analyze != 'true'"),
                condition.replace("matrix.language == 'rust'", "matrix.language != 'rust'")
                if case[0] == 0 else condition.replace("steps.test_only.outputs.skip != 'true'", "steps.test_only.outputs.skip == 'true'"),
                condition + " && github.actor == 'trusted'",
            )
            for activation in variants:
                with self.subTest(condition=condition, activation=activation):
                    self.codeql_fixture(*case)
                    self.fetch["if"] = activation
                    self.reject("unreviewed activation condition")

    def test_codeql_conditions_still_require_a_covering_prior_check(self):
        for index, case in enumerate(CODEQL_CASES):
            with self.subTest(condition=case[2]):
                self.codeql_fixture(*case)
                self.check["if"] = CODEQL_CASES[1 - index][2]
                self.reject("lacks a prior credential-free trust check")
                self.check["if"] = case[2]
                self.job["steps"] = [self.fetch, self.check]
                self.reject("lacks a prior credential-free trust check")

    def test_codeql_conditions_do_not_allow_reader_in_analysis(self):
        for case in CODEQL_CASES:
            with self.subTest(condition=case[2]):
                self.codeql_fixture(*case)
                self.fetch["run"] = "codeql database analyze database queries"
                self.reject("reader is not used by the reviewed fetch helper")

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
