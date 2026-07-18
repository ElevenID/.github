from __future__ import annotations

import pathlib
import tempfile
import unittest

import sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from scripts.workflow_policy import check_workflow  # noqa: E402


class WorkflowPolicyTests(unittest.TestCase):
    def check(self, source: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workflow.yml"
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
        ):
            self.assertIn(expected, joined)


if __name__ == "__main__":
    unittest.main()
