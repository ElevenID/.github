from __future__ import annotations

import datetime as dt
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from scripts.dependency_health import check_repository  # noqa: E402


class DependencyHealthTests(unittest.TestCase):
    def test_requires_health_file_for_code_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "package.json").write_text("{}", encoding="utf-8")
            self.assertIn("required", "\n".join(check_repository(root)))

    def test_accepts_current_dependency_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            (root / "dependency-health.yml").write_text(
                """version: 1
dependencies:
  - package: isomdl
    ecosystem: rust
    owner: ElevenID
    upstream: https://github.com/spruceid/isomdl
    current: 0.2.0
    target: replacement
    status: watch
    decision: replace
    advisories: [GHSA-example]
    tracking-issue: https://github.com/ElevenID/marty-core/issues/1
    review-after: 2027-01-01
    rationale: Replacement evaluation is active.
""",
                encoding="utf-8",
            )
            failures = check_repository(root, today=dt.date(2026, 7, 18))
            self.assertEqual([], failures)

    def test_rejects_expired_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "dependency-health.yml").write_text(
                """version: 1
dependencies:
  - package: glib
    ecosystem: rust
    owner: ElevenID
    upstream: https://github.com/gtk-rs/gtk-rs-core
    current: 0.18.5
    target: upstream
    status: temporary-exception
    decision: replace
    advisories: [GHSA-wrw7-89jp-8q8g]
    tracking-issue: ""
    review-after: 2026-01-01
    rationale: Waiting for the supported Tauri graph.
""",
                encoding="utf-8",
            )
            failures = check_repository(root, today=dt.date(2026, 7, 18))
            self.assertIn("expired", "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
