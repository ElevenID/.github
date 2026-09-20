from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from scripts import feature_regression_observation_runner as runner


REPOSITORY = "ElevenID/example"
REVISION = "a" * 40
POLICY_REF = "d" * 40
WORKFLOW_PATH = ".github/workflows/behavior-observations.yml"
HARNESS_PATH = ".github/feature-regression/observation_harness.py"
SUBJECT_PATH = ".github/feature-regression/behavior_subject.py"
OUTPUT_PATH = "artifacts/observations.json"
RUNTIME_IMAGE = (
    "python:3.12-alpine@sha256:"
    "236173eb74001afe2f60862de935b74fcbd00adfca247b2c27051a70a6a39a2d"
)

SUBJECT = textwrap.dedent(
    """
    import json
    import sys

    document = {
        "schema": "elevenid.behavior-subject-output/v2",
        "observations": [{
            "id": "approval-provider-failure.public_status",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "public_status",
            "value": "HTTP 502",
        }],
    }
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
    """
).lstrip()

HARNESS = textwrap.dedent(
    """
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("--repository")
    parser.add_argument("--revision")
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    args = parser.parse_args()
    capture = json.load(sys.stdin)
    if args.command == "test":
        if capture["schema"] != "elevenid.behavior-subject-capture/v2":
            raise SystemExit(1)
        raise SystemExit(0)
    observations = []
    for observed in capture["observations"]:
        observations.append({
            **observed,
            "id": f'{observed["case_id"]}.{observed["dimension"]}.{args.phase}',
            "producer_test": (
                f"test:{args.repository}@{args.revision}:tests/test_api.py::"
                "test_approval_provider_failure"
            ),
        })
    document = {
        "schema": "elevenid.behavior-observations-runtime/v2",
        "repository": args.repository,
        "revision": args.revision,
        "phase": args.phase,
        "observations": observations,
    }
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
    """
).lstrip()


class ObservationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.previous_cwd = pathlib.Path.cwd()
        os.chdir(self.root)
        self.harness = self.root / HARNESS_PATH
        self.harness.parent.mkdir(parents=True)
        self.harness.write_text(HARNESS, encoding="utf-8")
        self.subject = self.root / SUBJECT_PATH
        self.subject.write_text(SUBJECT, encoding="utf-8")
        workflow = self.root / WORKFLOW_PATH
        workflow.parent.mkdir(parents=True)
        workflow.write_text("stable caller workflow\n", encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        self.subject_digest = self.digest(self.subject)
        self.container_patch = mock.patch.object(
            runner, "_run_container", side_effect=self.run_fake_container
        )
        self.container_mock = self.container_patch.start()

    def tearDown(self) -> None:
        if self.container_patch is not None:
            self.container_patch.stop()
        os.chdir(self.previous_cwd)
        self.temporary.cleanup()

    @staticmethod
    def digest(path: pathlib.Path) -> str:
        return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"

    @staticmethod
    def setsid_subject_source() -> str:
        return SUBJECT.replace(
            "import sys\n", "import sys\nimport os\nimport pathlib\nimport time\n"
        ).replace(
            "document = {",
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    os.close(1)\n"
            "    os.close(2)\n"
            f"    target = pathlib.Path({OUTPUT_PATH!r})\n"
            "    deadline = time.monotonic() + 2\n"
            "    while time.monotonic() < deadline:\n"
            "        if target.exists():\n"
            "            try:\n"
            "                payload = json.loads(target.read_text())\n"
            "                payload['observations'][0]['value'] = 'FABRICATED'\n"
            "                target.write_text(json.dumps(payload, sort_keys=True, separators=(',', ':')))\n"
            "                os._exit(0)\n"
            "            except (OSError, ValueError, KeyError, IndexError):\n"
            "                pass\n"
            "        time.sleep(0.02)\n"
            "    os._exit(0)\n"
            "document = {",
        )

    def run_fake_container(
        self,
        args: object,
        workload: list[str],
        environment: dict[str, str],
        *,
        label: str,
        timeout: float,
        stdout_limit: int,
        stderr_limit: int,
        stdin_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        del args
        command = list(workload)
        if command[0] == "python3":
            command[0] = sys.executable
        if command[1].startswith("/workspace/"):
            command[1] = str(self.root / command[1].removeprefix("/workspace/"))
        return runner._run_process(
            command,
            {**os.environ, **environment},
            label=label,
            timeout=timeout,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            stdin_data=stdin_data,
        )

    def contract(
        self,
        *,
        harness_path: str = HARNESS_PATH,
        subject_path: str = SUBJECT_PATH,
        runtime_image: str = RUNTIME_IMAGE,
        phase: str = "after",
        event_name: str = "pull_request",
        head_branch: str = "feature/probe",
    ) -> list[str]:
        return [
            "--harness-path",
            harness_path,
            "--harness-sha256",
            self.harness_digest,
            "--subject-path",
            subject_path,
            "--subject-sha256",
            self.subject_digest,
            "--subject-runtime",
            "python",
            "--subject-args-json",
            "[]",
            "--subject-env-json",
            "{}",
            "--runtime-image",
            runtime_image,
            "--output",
            OUTPUT_PATH,
            "--repository",
            REPOSITORY,
            "--revision",
            REVISION,
            "--phase",
            phase,
            "--event-name",
            event_name,
            "--head-branch",
            head_branch,
            "--workflow-path",
            WORKFLOW_PATH,
            "--policy-ref",
            POLICY_REF,
            "--job-name",
            "behavior-observations / Behavior observation producer",
            "--artifact-name",
            "feature-regression-observations-12345-2",
            "--run-id",
            "12345",
            "--run-attempt",
            "2",
        ]

    def produce(self, **paths: str) -> int:
        return runner.main(["produce", *self.contract(**paths)])

    def reset_output(self) -> None:
        output = self.root / OUTPUT_PATH
        if output.exists():
            output.unlink()

    def test_end_to_end_atomic_runner_owned_receipt_and_observations(self) -> None:
        self.assertEqual(0, self.produce())
        document = json.loads((self.root / OUTPUT_PATH).read_bytes())
        receipt = document["runtime_receipt"]
        expected_stdout = SUBJECT.encode()
        namespace: dict[str, object] = {}
        with mock.patch("sys.stdout.write") as write:
            exec(expected_stdout, namespace)
        actual_stdout = write.call_args.args[0].encode()
        self.assertEqual(SUBJECT_PATH, receipt["subject_path"])
        self.assertEqual(self.subject_digest, receipt["subject_sha256"])
        self.assertEqual(RUNTIME_IMAGE, receipt["runtime_image"])
        self.assertEqual(RUNTIME_IMAGE, document["producer"]["runtime_image"])
        self.assertEqual(
            f"sha256:{hashlib.sha256(actual_stdout).hexdigest()}",
            receipt["stdout_sha256"],
        )
        self.assertEqual(
            f"sha256:{hashlib.sha256(b'').hexdigest()}", receipt["stderr_sha256"]
        )
        self.assertEqual("HTTP 502", document["observations"][0]["value"])
        self.assertEqual("after", document["phase"])
        self.assertEqual("pull_request", document["producer"]["event_name"])
        calls = self.container_mock.call_args_list
        self.assertEqual(3, len(calls))
        self.assertIsNone(calls[0].kwargs.get("stdin_data"))
        self.assertIsInstance(calls[1].kwargs.get("stdin_data"), bytes)
        self.assertEqual(
            calls[1].kwargs.get("stdin_data"), calls[2].kwargs.get("stdin_data")
        )
        for call in calls:
            workload = call.args[1]
            self.assertNotIn("--input", workload)
            self.assertNotIn("--output", workload)
            self.assertNotIn(OUTPUT_PATH, " ".join(workload))
        self.assertFalse(
            any(
                path.name.startswith(".elevenid-feature-review-")
                for path in (self.root / "artifacts").iterdir()
            )
        )

    def test_before_phase_requires_a_main_refresh_event(self) -> None:
        self.assertEqual(
            0,
            self.produce(
                phase="before", event_name="workflow_dispatch", head_branch="main"
            ),
        )
        document = json.loads((self.root / OUTPUT_PATH).read_bytes())
        self.assertEqual("before", document["phase"])
        self.assertEqual("before", document["producer"]["phase"])
        self.assertEqual("main", document["producer"]["head_branch"])

    def test_phase_event_and_branch_substitution_fail_closed(self) -> None:
        invalid = (
            {"phase": "before", "event_name": "pull_request", "head_branch": "main"},
            {"phase": "before", "event_name": "push", "head_branch": "feature/x"},
            {"phase": "after", "event_name": "push", "head_branch": "main"},
        )
        for contract in invalid:
            with self.subTest(contract=contract):
                self.assertEqual(1, self.produce(**contract))
                self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_cross_step_capture_tampering_exploit_has_no_trusted_reload_phase(
        self,
    ) -> None:
        self.assertEqual(0, self.produce())
        output = self.root / OUTPUT_PATH
        trusted = output.read_bytes()
        final = json.loads(trusted)
        fabricated_capture = {
            "schema": "elevenid.behavior-subject-capture/v2",
            "receipt": final["runtime_receipt"],
            "observations": [
                {
                    key: value
                    for key, value in final["observations"][0].items()
                    if key != "producer_test"
                }
            ],
        }
        fabricated_capture["observations"][0]["value"] = "HTTP 599"
        capture_path = self.root / "forged-capture.json"
        self.assertNotEqual(
            runner._canonical(fabricated_capture),
            trusted,
        )
        for legacy_phase in ("invoke", "test", "generate", "validate"):
            with self.subTest(legacy_phase=legacy_phase):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        runner.main(
                            [
                                legacy_phase,
                                "--capture",
                                str(capture_path),
                                *self.contract(),
                            ]
                        )
        self.assertEqual(trusted, output.read_bytes())

    def test_harness_and_subject_swap_path_symlink_and_digest_fail_closed(self) -> None:
        self.harness.write_text(HARNESS + "# swap\n", encoding="utf-8")
        self.assertEqual(1, self.produce())
        self.harness.write_text(HARNESS, encoding="utf-8")
        self.subject.write_text(SUBJECT + "# swap\n", encoding="utf-8")
        self.assertEqual(1, self.produce())
        self.subject.write_text(SUBJECT, encoding="utf-8")
        for blocked_path in (self.harness, self.subject):
            with self.subTest(symlink=blocked_path.name):
                with mock.patch.object(
                    pathlib.Path,
                    "is_symlink",
                    autospec=True,
                    side_effect=lambda path, blocked=blocked_path: path == blocked,
                ):
                    self.assertEqual(1, self.produce())
        self.assertEqual(1, self.produce(subject_path="../behavior_subject.py"))

    @unittest.skipUnless(os.name == "posix", "real symlink semantics require POSIX")
    def test_real_lexical_file_symlink_is_rejected_before_resolution(self) -> None:
        real_subject = self.root / "real_behavior_subject.py"
        real_subject.write_text(SUBJECT, encoding="utf-8")
        self.subject.unlink()
        self.subject.symlink_to(real_subject)

        self.assertEqual(real_subject, self.subject.resolve())
        self.assertTrue(self.subject.is_symlink())
        self.assertEqual(1, self.produce())
        self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_executable_mutation_during_subject_and_harness_runs_fails_closed(
        self,
    ) -> None:
        cases = (
            (
                "subject mutates itself",
                SUBJECT.replace(
                    "document = {",
                    f"pathlib.Path({str(self.subject)!r}).write_text('changed')\n"
                    "document = {",
                ).replace("import sys\n", "import sys\nimport pathlib\n"),
                HARNESS,
            ),
            (
                "subject mutates harness",
                SUBJECT.replace(
                    "document = {",
                    f"pathlib.Path({str(self.harness)!r}).write_text('changed')\n"
                    "document = {",
                ).replace("import sys\n", "import sys\nimport pathlib\n"),
                HARNESS,
            ),
            (
                "harness test mutates itself",
                SUBJECT,
                HARNESS.replace(
                    'if args.command == "test":',
                    'if args.command == "test":\n'
                    f"    pathlib.Path({str(self.harness)!r}).write_text('changed')",
                ).replace("import sys\n", "import sys\nimport pathlib\n"),
            ),
            (
                "harness emit mutates itself",
                SUBJECT,
                HARNESS.replace(
                    "sys.stdout.write(",
                    f"pathlib.Path({str(self.harness)!r}).write_text('changed')\n"
                    "sys.stdout.write(",
                ).replace("import sys\n", "import sys\nimport pathlib\n"),
            ),
        )
        for label, subject_source, harness_source in cases:
            with self.subTest(label=label):
                self.subject.write_text(subject_source, encoding="utf-8")
                self.harness.write_text(harness_source, encoding="utf-8")
                self.subject_digest = self.digest(self.subject)
                self.harness_digest = self.digest(self.harness)
                self.assertEqual(1, self.produce())
                self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_subject_timeout_output_limits_exit_and_json_fail_closed(self) -> None:
        cases = (
            ("import time\ntime.sleep(2)\n", {"SUBJECT_TIMEOUT_SECONDS": 0.05}),
            ("import sys\nsys.stdout.write('x' * 100)\n", {"MAX_SUBJECT_STDOUT": 10}),
            ("import sys\nsys.stderr.write('x' * 100)\n", {"MAX_SUBJECT_STDERR": 10}),
            ("raise SystemExit(7)\n", {}),
            ("print('{not-json')\n", {}),
        )
        for source, patches in cases:
            with self.subTest(source=source):
                self.subject.write_text(source, encoding="utf-8")
                self.subject_digest = self.digest(self.subject)
                patchers = [
                    mock.patch.object(runner, name, value)
                    for name, value in patches.items()
                ]
                for patcher in patchers:
                    patcher.start()
                try:
                    self.assertEqual(1, self.produce())
                    self.assertFalse((self.root / OUTPUT_PATH).exists())
                finally:
                    for patcher in reversed(patchers):
                        patcher.stop()

    def test_harness_cannot_fabricate_receipt_or_observation(self) -> None:
        exploit = HARNESS.replace(
            '    "observations": observations,',
            '    "observations": observations,\n'
            '    "runtime_receipt": {"exit_code": 0},',
        )
        self.assertNotEqual(HARNESS, exploit)
        self.harness.write_text(exploit, encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        self.assertEqual(1, self.produce())
        self.assertFalse((self.root / OUTPUT_PATH).exists())

        forged = HARNESS.replace(
            '        "producer_test": (',
            '        "value": "".join(["for", "ged"]),\n        "producer_test": (',
        )
        self.assertNotEqual(HARNESS, forged)
        self.harness.write_text(forged, encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        self.assertEqual(1, self.produce())

    def test_dynamic_literal_harness_cannot_mask_a_subject_regression(self) -> None:
        self.subject.write_text(
            SUBJECT.replace('"HTTP 502"', '"HTTP 503"'), encoding="utf-8"
        )
        self.subject_digest = self.digest(self.subject)
        dynamic_old_value = HARNESS.replace(
            '        "producer_test": (',
            '        "value": "".join(["HTTP", " 502"]),\n        "producer_test": (',
        )
        self.assertNotEqual(HARNESS, dynamic_old_value)
        self.harness.write_text(dynamic_old_value, encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        self.assertEqual(1, self.produce())
        self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_harness_timeout_and_output_bound_leave_no_output(self) -> None:
        hanging = "import time\ntime.sleep(2)\n"
        self.harness.write_text(hanging, encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        with mock.patch.object(runner, "HARNESS_TIMEOUT_SECONDS", 0.05):
            self.assertEqual(1, self.produce())
        self.assertFalse((self.root / OUTPUT_PATH).exists())

        self.harness.write_text(HARNESS, encoding="utf-8")
        self.harness_digest = self.digest(self.harness)
        with mock.patch.object(runner, "MAX_HARNESS_OBSERVATION_BYTES", 10):
            self.assertEqual(1, self.produce())
        self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_container_contract_is_read_only_private_bounded_and_path_blind(
        self,
    ) -> None:
        command = runner._container_command(
            docker="/usr/bin/docker",
            image=RUNTIME_IMAGE,
            name="elevenid-feature-review-test",
            workload=["python3", f"/workspace/{SUBJECT_PATH}"],
            environment=runner.FIXED_ENVIRONMENT,
        )
        for required in (
            "--rm",
            "--interactive",
            "--pull=missing",
            "--init",
            "--network=none",
            "--read-only",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=256m",
            "--cpus=1",
            "--user=65534:65534",
            "--workdir=/workspace",
        ):
            self.assertIn(required, command)
        mount = command[command.index("--mount") + 1]
        self.assertIn("target=/workspace", mount)
        self.assertTrue(mount.endswith(",readonly"))
        serialized = " ".join(command)
        self.assertNotIn(OUTPUT_PATH, serialized)
        self.assertNotIn("subject-capture", serialized)
        self.assertNotIn("harness-output", serialized)
        self.assertNotIn("--pid=host", command)

    def test_unpinned_runtime_image_is_rejected_before_execution(self) -> None:
        self.assertEqual(1, self.produce(runtime_image="python:3.12-alpine"))
        self.assertFalse((self.root / OUTPUT_PATH).exists())

    def test_container_is_forcibly_removed_when_client_execution_fails(self) -> None:
        self.container_patch.stop()
        self.container_patch = None
        args = mock.Mock(runtime_image=RUNTIME_IMAGE)
        with (
            mock.patch.object(runner, "_docker_binary", return_value="/docker"),
            mock.patch.object(
                runner,
                "_run_process",
                side_effect=runner.RunnerError("subject invocation timed out"),
            ),
            mock.patch.object(runner, "_remove_container") as remove,
            mock.patch.object(runner.secrets, "token_hex", return_value="a" * 24),
        ):
            with self.assertRaisesRegex(runner.RunnerError, "timed out"):
                runner._run_container(
                    args,
                    ["python3", f"/workspace/{SUBJECT_PATH}"],
                    runner.FIXED_ENVIRONMENT,
                    label="subject",
                    timeout=0.01,
                    stdout_limit=10,
                    stderr_limit=10,
                )
        remove.assert_called_once_with("/docker", f"elevenid-feature-review-{'a' * 24}")

    @unittest.skipUnless(os.name == "posix", "setsid is a POSIX primitive")
    def test_setsid_descendant_reproduces_the_old_cross_step_rewrite(self) -> None:
        target = self.root / OUTPUT_PATH
        target.parent.mkdir(parents=True)
        self.subject.write_text(self.setsid_subject_source(), encoding="utf-8")
        subprocess.run(
            [sys.executable, str(self.subject)],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=5,
        )
        target.write_text(
            json.dumps(
                {"observations": [{"value": "HTTP 502"}]},
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        time.sleep(0.4)
        self.assertEqual(
            "FABRICATED", json.loads(target.read_text())["observations"][0]["value"]
        )

    def test_setsid_descendant_cannot_rewrite_atomic_host_artifact(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("Docker is required for the namespace escape regression")
        probe = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if probe.returncode != 0:
            self.skipTest("a Linux Docker engine is required")
        self.container_patch.stop()
        self.container_patch = None
        self.root.chmod(0o755)
        self.harness.parent.chmod(0o755)
        self.harness.chmod(0o644)
        target = self.root / OUTPUT_PATH
        target.parent.mkdir(parents=True)
        target.parent.chmod(0o755)
        source = self.setsid_subject_source()
        self.subject.write_text(source, encoding="utf-8")
        self.subject.chmod(0o644)
        self.subject_digest = self.digest(self.subject)

        self.assertEqual(0, self.produce())
        trusted = target.read_bytes()
        time.sleep(0.5)
        self.assertEqual(trusted, target.read_bytes())
        self.assertEqual("HTTP 502", json.loads(trusted)["observations"][0]["value"])

    def test_existing_final_output_is_never_overwritten(self) -> None:
        output = self.root / OUTPUT_PATH
        output.parent.mkdir(parents=True)
        output.write_bytes(b"existing")
        self.assertEqual(1, self.produce())
        self.assertEqual(b"existing", output.read_bytes())

    def test_racing_destination_is_never_overwritten_and_temp_is_cleaned(self) -> None:
        output = self.root / OUTPUT_PATH
        output.parent.mkdir(parents=True)
        competitor = b"competitor-owned"
        real_link = os.link

        def create_destination_then_link(
            source: os.PathLike[str] | str,
            destination: os.PathLike[str] | str,
            *args: object,
            **kwargs: object,
        ) -> None:
            pathlib.Path(destination).write_bytes(competitor)
            real_link(source, destination, *args, **kwargs)

        with mock.patch.object(os, "link", side_effect=create_destination_then_link):
            self.assertEqual(1, self.produce())
        self.assertEqual(competitor, output.read_bytes())
        self.assertEqual([], list(output.parent.glob(f".{output.name}.*.tmp")))


if __name__ == "__main__":
    unittest.main()
