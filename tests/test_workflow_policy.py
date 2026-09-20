from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from scripts import workflow_policy  # noqa: E402

check_workflow = workflow_policy.check_workflow
check_paths = workflow_policy.check_paths


class WorkflowPolicyTests(unittest.TestCase):
    def check(self, source: str, filename: str = "workflow.yml") -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / filename
            path.write_text(source, encoding="utf-8")
            return check_workflow(path)

    def test_accepts_pinned_standard_runner_workflow(self) -> None:
        failures = self.check(
            """
name: Safe
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
"""
        )
        self.assertEqual([], failures)

    def test_rejects_eol_node_and_node20_action_runtime(self) -> None:
        failures = self.check(
            """
name: Stale Node
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020
        with:
          node-version: "20"
"""
        )
        joined = "\n".join(failures)
        self.assertIn("unsupported Node 20 Action runtime", joined)
        self.assertIn("use Node 24", joined)

    def test_rejects_all_high_risk_constructs(self) -> None:
        failures = self.check(
            """
name: Unsafe
# elevenid:required
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@main
      - run: scanner --exit-zero || true
        continue-on-error: true
"""
        )
        joined = "\n".join(failures)
        for expected in (
            "not pinned",
            "pull_request_target",
            "write-all",
            "ignore failures",
            "failure-masking",
            "self-hosted",
            "merge_group",
        ):
            self.assertIn(expected, joined)

    def test_accepts_required_merge_queue_workflow(self) -> None:
        failures = self.check(
            """
name: Merge queue safe
# elevenid:required
on:
  pull_request:
  merge_group:
    types: [checks_requested]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
"""
        )
        self.assertEqual([], failures)

    def test_rejects_mutating_or_direct_feature_regression_gate(self) -> None:
        failures = self.check(
            """
name: Reusable feature-regression review
on:
  pull_request:
permissions:
  actions: read
  contents: write
  issues: read
  pull-requests: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo unsafe
"""
        )
        joined = "\n".join(failures)
        self.assertIn("must use only workflow_call", joined)
        self.assertIn("permissions must be exactly", joined)
        self.assertIn("may not request write permission", joined)

    def test_accepts_pinned_feature_review_call_with_matching_policy_ref(self) -> None:
        sha = "a" * 40
        with mock.patch.object(
            workflow_policy, "APPROVED_FEATURE_REVIEW_REVISION", sha
        ):
            failures = self.check(
                f"""
name: feature-regression-review
on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]
permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read
jobs:
  feature-regression-review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@{sha}
    with:
      policy-ref: {sha}
""",
                "feature-regression-review-caller.yml",
            )
        self.assertEqual([], failures)

    def test_rejects_unapproved_feature_review_revision(self) -> None:
        sha = "a" * 40
        with mock.patch.object(
            workflow_policy, "APPROVED_FEATURE_REVIEW_REVISION", "b" * 40
        ):
            failures = self.check(
                f"""
name: feature-regression-review
on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]
permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read
jobs:
  feature-regression-review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@{sha}
    with:
      policy-ref: {sha}
""",
                "feature-regression-review-caller.yml",
            )
        self.assertIn("single trusted approved revision", "\n".join(failures))

    def test_rejects_feature_caller_without_actions_read(self) -> None:
        sha = "a" * 40
        with mock.patch.object(
            workflow_policy, "APPROVED_FEATURE_REVIEW_REVISION", sha
        ):
            failures = self.check(
                f"""
name: feature-regression-review
on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]
permissions:
  contents: read
  issues: read
  pull-requests: read
jobs:
  feature-regression-review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@{sha}
    with:
      policy-ref: {sha}
""",
                "feature-regression-review-caller.yml",
            )
        self.assertIn("caller permissions must be exactly", "\n".join(failures))

    def test_reserved_caller_filename_is_enforced_without_a_real_call(self) -> None:
        failures = self.check(
            """
name: Harmless lookalike
on: [push]
permissions:
  contents: read
concurrency: fake
jobs:
  fake:
    runs-on: ubuntu-latest
    steps:
      - run: echo skipped
""",
            "feature-regression-review-caller.yml",
        )
        joined = "\n".join(failures)
        self.assertIn("caller permissions must be exactly", joined)
        self.assertIn("exact root schema", joined)
        self.assertIn("exact feature-regression-review job id", joined)

        failures = self.check(
            f"""
name: feature-regression-review
on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]
permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read
jobs:
  feature-regression-review:
    uses: Attacker/lookalike/.github/workflows/review.yml@{"a" * 40}
    with:
      policy-ref: {"a" * 40}
""",
            "feature-regression-review-caller.yml",
        )
        self.assertIn("reserved caller must call ElevenID/.github", "\n".join(failures))

    def test_enabled_repository_requires_reserved_caller_in_scanned_workflows(
        self,
    ) -> None:
        repository = "ElevenID/example"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "feature-regression-review-lookalike.yml").write_text(
                "name: lookalike\non: [push]\njobs: {}\n", encoding="utf-8"
            )
            with mock.patch.object(
                workflow_policy,
                "ENABLED_FEATURE_REVIEW_REPOSITORIES",
                {repository.casefold()},
            ):
                failures = check_paths(
                    [workflows], repository=repository, repository_root=root
                )
            self.assertIn("enabled feature review requires", "\n".join(failures))

    def test_workflow_scan_requires_explicit_repository_identity(self) -> None:
        self.assertIn(
            "explicit owner/repository",
            "\n".join(check_paths([], repository="")),
        )

    def test_rejects_filtered_skippable_or_extra_feature_caller_controls(self) -> None:
        sha = "a" * 40
        unsafe_fragments = (
            "types: [opened]",
            "paths: ['src/**']",
            "if: github.actor != 'blocked'",
            "needs: build",
            "continue-on-error: true",
            "strategy:\n      matrix:\n        shard: [1, 2]",
        )
        for fragment in unsafe_fragments:
            with (
                self.subTest(fragment=fragment),
                mock.patch.object(
                    workflow_policy, "APPROVED_FEATURE_REVIEW_REVISION", sha
                ),
            ):
                if fragment.startswith(("types:", "paths:")):
                    pull_request = (
                        "pull_request:\n    branches: [main]\n    " + fragment
                    )
                    job_extra = ""
                else:
                    pull_request = "pull_request:\n    branches: [main]"
                    job_extra = "\n    " + fragment.replace("\n", "\n    ")
                failures = self.check(
                    f"""
name: feature-regression-review
on:
  {pull_request}
  merge_group:
    types: [checks_requested]
permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read
jobs:
  feature-regression-review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@{sha}
    with:
      policy-ref: {sha}{job_extra}
""",
                    "feature-regression-review-caller.yml",
                )
                joined = "\n".join(failures)
                self.assertTrue(
                    "triggers must be exact" in joined
                    or "skip/masking controls are prohibited" in joined
                )

    def test_rejects_local_dynamic_unpinned_or_mismatched_feature_calls(self) -> None:
        valid_sha = "a" * 40
        invalid_calls = (
            ("./.github/workflows/feature-regression-review.yml", valid_sha),
            (
                "ElevenID/.github/.github/workflows/feature-regression-review.yml@main",
                valid_sha,
            ),
            (
                "ElevenID/.github/.github/workflows/feature-regression-review.yml@${{ github.sha }}",
                valid_sha,
            ),
            (
                "ElevenID/.github/.github/workflows/feature-regression-review.yml@"
                + valid_sha,
                "b" * 40,
            ),
        )
        for uses, policy_ref in invalid_calls:
            with self.subTest(uses=uses, policy_ref=policy_ref):
                failures = self.check(
                    f"""
name: Unsafe caller
on: [merge_group]
jobs:
  review:
    uses: {uses}
    with:
      policy-ref: {policy_ref}
"""
                )
                joined = "\n".join(failures)
                self.assertTrue(
                    "literal full commit SHA" in joined
                    or "policy-ref must equal the uses SHA" in joined
                )

    def test_rejects_dynamic_or_missing_policy_ref_on_pinned_call(self) -> None:
        sha = "a" * 40
        for inputs in (
            "with:\n      policy-ref: ${{ github.sha }}",
            "",
        ):
            with self.subTest(inputs=inputs):
                failures = self.check(
                    f"""
name: Unsafe policy ref
on: [merge_group]
jobs:
  review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@{sha}
    {inputs}
"""
                )
                self.assertIn(
                    "policy-ref must be a literal full commit SHA",
                    "\n".join(failures),
                )


if __name__ == "__main__":
    unittest.main()
