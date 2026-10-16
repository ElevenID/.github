import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prune_local_evidence.py"
SPEC = importlib.util.spec_from_file_location("prune_local_evidence", SCRIPT)
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


class LocalEvidenceRetentionTests(unittest.TestCase):
    def test_only_expired_disposable_trees_are_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            now = time.time()
            old = now - 40 * 86400
            for name in (
                "expired",
                "recent",
                "nested-repo",
                "predeletion-backup",
                "linked",
            ):
                path = root / "artifacts" / name
                path.mkdir(parents=True)
                (path / "report.json").write_text("{}")
            (root / "artifacts/nested-repo/.git").write_text("gitdir: elsewhere")
            try:
                (root / "artifacts/linked/link").symlink_to(
                    root / "artifacts/recent/report.json"
                )
            except OSError:
                # Windows may disallow symlink creation without developer mode.
                (root / "artifacts/linked/report.json").unlink()
                (root / "artifacts/linked").rmdir()
            (root / "worktrees/old").mkdir(parents=True)
            (root / "_codex-diagnostics/expired").mkdir(parents=True)
            for base, dirs, files in os.walk(root, topdown=False):
                for name in files:
                    path = Path(base) / name
                    if not path.is_symlink():
                        os.utime(path, (old, old))
                os.utime(base, (old, old))
            # A newly modified descendant keeps the whole evidence tree.
            os.utime(root / "artifacts/recent/report.json", (now, now))
            found = {
                p.relative_to(root).as_posix()
                for p, _, _ in cleanup.candidates(root, now)
            }
            self.assertEqual(found, {"artifacts/expired", "_codex-diagnostics/expired"})
            preview = subprocess.run(
                [sys.executable, str(SCRIPT), str(root)],
                capture_output=True,
                check=False,
            )
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertTrue((root / "artifacts/expired").exists())
            applied = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), "--apply"],
                capture_output=True,
                check=False,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertFalse((root / "artifacts/expired").exists())
            self.assertTrue((root / "artifacts/recent/report.json").exists())
            self.assertTrue((root / "artifacts/nested-repo/.git").exists())
            self.assertTrue((root / "worktrees/old").exists())

    def test_nested_mount_is_rejected_before_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            nested = path / "ordinary" / "mounted"
            with (
                patch.object(cleanup, "mount_points", return_value={nested}),
                patch.object(cleanup.os, "walk") as walk,
            ):
                self.assertIsNone(cleanup.inspect(path))
                walk.assert_not_called()

    def test_mounted_container_and_candidate_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate = root / "artifacts" / "old"
            candidate.mkdir(parents=True)
            os.utime(candidate, (0, 0))
            for mount in (candidate.parent, candidate):
                with patch.object(cleanup, "mount_points", return_value={mount}):
                    self.assertEqual(list(cleanup.candidates(root, time.time())), [])
                    with self.assertRaises(ValueError):
                        cleanup.validate_target(root, candidate)

    def test_linux_bind_mount_table_decodes_escaped_paths(self):
        table = "31 22 8:1 /source /scratch/a\\040b rw - ext4 /dev/root rw\n"
        with (
            patch.object(cleanup.sys, "platform", "linux"),
        ):
            with patch.object(Path, "read_text", return_value=table):
                self.assertEqual(cleanup.mount_points(), {Path("/scratch/a b")})
            with (
                patch.object(Path, "read_text", side_effect=PermissionError),
                self.assertRaises(PermissionError),
            ):
                cleanup.mount_points()

    def test_apply_rechecks_new_nested_mount_before_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate = root / "artifacts" / "old"
            candidate.mkdir(parents=True)
            os.utime(candidate, (0, 0))
            original = cleanup.candidates
            mounts = set()

            def mounted_candidates(workspace, now):
                selected = list(original(workspace, now))
                self.assertEqual(len(selected), 1)
                mounts.add(candidate / "new-volume")
                yield from selected

            with (
                patch.object(cleanup, "mount_points", side_effect=lambda: mounts),
                patch.object(cleanup, "candidates", mounted_candidates),
                patch.object(cleanup.shutil, "rmtree") as delete,
                patch.object(sys, "argv", [str(SCRIPT), str(root), "--apply"]),
            ):
                cleanup.main()
                delete.assert_not_called()
            self.assertTrue(candidate.exists())

    def test_container_that_is_a_repository_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "artifacts/.git").mkdir(parents=True)
            (root / "artifacts/old.log").write_text("output")
            os.utime(root / "artifacts/old.log", (0, 0))
            self.assertEqual(list(cleanup.candidates(root, time.time())), [])

    def test_windows_reparse_points_are_protected(self):
        path = Mock()
        path.is_symlink.return_value = False
        path.lstat.return_value.st_file_attributes = 0x400
        self.assertTrue(cleanup.linked(path))

    def test_nested_backup_or_installation_preserves_its_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for index, marker in enumerate(cleanup.PRESERVE):
                path = root / "artifacts" / f"job-{index}" / "ordinary" / marker
                path.mkdir(parents=True)
                (path / "state.json").write_text("{}")
            for base, dirs, files in os.walk(root, topdown=False):
                for name in files:
                    os.utime(Path(base) / name, (0, 0))
                os.utime(base, (0, 0))
            self.assertEqual(list(cleanup.candidates(root, time.time())), [])

    def test_recursive_delete_target_must_be_a_bounded_scratch_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for path in (root, root / "worktrees" / "owned", root.parent):
                with self.assertRaises(ValueError):
                    cleanup.validate_target(root, path)

    def test_container_with_git_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "artifacts").mkdir()
            (root / "artifacts/.git").write_text("gitdir: owned elsewhere")
            (root / "artifacts/old.log").write_text("old")
            os.utime(root / "artifacts/old.log", (0, 0))
            self.assertEqual(list(cleanup.candidates(root, time.time())), [])

    def test_apply_rechecks_fresh_descendant_before_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report = root / "artifacts/job/report.json"
            report.parent.mkdir(parents=True)
            report.write_text("{}")
            os.utime(report, (0, 0))
            os.utime(report.parent, (0, 0))
            original = cleanup.candidates

            def modified_candidates(workspace, now):
                selected = list(original(workspace, now))
                self.assertEqual(len(selected), 1)
                os.utime(report, None)
                yield from selected

            with (
                patch.object(cleanup, "candidates", modified_candidates),
                patch.object(sys, "argv", [str(SCRIPT), str(root), "--apply"]),
            ):
                cleanup.main()
            self.assertTrue(report.exists())


if __name__ == "__main__":
    unittest.main()
