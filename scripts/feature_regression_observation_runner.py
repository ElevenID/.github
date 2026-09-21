from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
from typing import Any, BinaryIO


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
TEST_REFERENCE = re.compile(
    r"^test:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<commit>[0-9a-f]{40}):(?P<path>[A-Za-z0-9_.\-/]+)::"
    r"(?P<test>[A-Za-z0-9_.:/#\-\[\]]+)$"
)
OCI_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,254}@sha256:[0-9a-f]{64}$")
SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9_.\-/]{1,512}$")
DIMENSIONS = {"public_status", "public_message", "safe_server_diagnostic"}
FIXED_ENVIRONMENT = {"LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0", "TZ": "UTC"}
RUST_FIXED_ENVIRONMENT = {
    **FIXED_ENVIRONMENT,
    "CARGO_HOME": "/build/cargo-home",
    "CARGO_NET_OFFLINE": "true",
    "CARGO_TARGET_DIR": "/build/target",
    "HOME": "/build/home",
    "PATH": "/opt/elevenid/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
    "RUSTUP_HOME": "/usr/local/rustup",
    "TMPDIR": "/tmp",
}
# Rust execution is deliberately unavailable until a reviewed runtime is
# published. A follow-up policy revision must add the exact image reference and
# the raw SHA-256 of /opt/elevenid/runtime-manifest.json together.
APPROVED_RUST_RUNTIME_IMAGES: dict[str, str] = {}
SUBJECT_TIMEOUT_SECONDS = 30.0
RUST_SUBJECT_TIMEOUT_SECONDS = 600.0
HARNESS_TIMEOUT_SECONDS = 30.0
MAX_SUBJECT_STDOUT = 1_048_576
MAX_SUBJECT_STDERR = 65_536
MAX_HARNESS_STDOUT = 65_536
MAX_HARNESS_STDERR = 65_536
MAX_HARNESS_OBSERVATION_BYTES = 2 * 1024 * 1024
RUST_BUILD_FIELDS = {
    "profile",
    "manifest_path",
    "manifest_sha256",
    "lock_path",
    "lock_sha256",
    "runtime_manifest_sha256",
}
RUST_RESERVED_ENVIRONMENT = {
    "BASH_ENV",
    "ENV",
    "HOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTDOC",
    "SHELL",
    "TMP",
    "TMPDIR",
    "TEMP",
}


class RunnerError(ValueError):
    """The immutable observation producer contract was violated."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RunnerError(f"non-finite JSON constant {value}")


def _parse_json(content: bytes, label: str) -> Any:
    try:
        return json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"{label} is not strict JSON: {error}") from error


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _safe_path(value: str, label: str) -> pathlib.Path:
    parts = value.split("/")
    if (
        SAFE_RELATIVE_PATH.fullmatch(value) is None
        or value.startswith("/")
        or not all(parts)
        or any(part in {".", ".."} for part in parts)
    ):
        raise RunnerError(f"{label} must be a safe repository-relative path")
    candidate = pathlib.PurePosixPath(value)
    root = pathlib.Path.cwd().resolve()
    lexical = root.joinpath(*candidate.parts)
    resolved = lexical.resolve()
    if root != resolved and root not in resolved.parents:
        raise RunnerError(f"{label} escapes the workspace")
    return lexical


def _verify_file(path: pathlib.Path, expected_digest: str, label: str) -> None:
    if not DIGEST.fullmatch(expected_digest):
        raise RunnerError(f"{label} digest is invalid")
    if path.is_symlink() or not path.is_file():
        raise RunnerError(f"{label} must be an existing regular non-symlink file")
    actual = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    if actual != expected_digest:
        raise RunnerError(f"{label} digest does not match")


def _file_digest(path: pathlib.Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise RunnerError(f"{label} must be a regular non-symlink file")
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _json_cli(value: str, label: str) -> Any:
    return _parse_json(value.encode("utf-8"), label)


def _subject_spec(args: argparse.Namespace) -> tuple[list[str], dict[str, str]]:
    raw_arguments = _json_cli(args.subject_args_json, "subject args")
    if not isinstance(raw_arguments, list) or any(
        not isinstance(item, str)
        or not item
        or len(item) > 256
        or any(ord(character) < 32 for character in item)
        for item in raw_arguments
    ):
        raise RunnerError("subject args must be a JSON array of safe strings")
    raw_environment = _json_cli(args.subject_env_json, "subject environment")
    if not isinstance(raw_environment, dict):
        raise RunnerError("subject environment must be a JSON object")
    environment = dict(FIXED_ENVIRONMENT)
    for name, value in raw_environment.items():
        if (
            not isinstance(name, str)
            or ENVIRONMENT_NAME.fullmatch(name) is None
            or name in FIXED_ENVIRONMENT
            or not isinstance(value, str)
            or len(value) > 512
            or any(ord(character) < 32 for character in value)
        ):
            raise RunnerError("subject environment contains an unsafe entry")
        if args.subject_runtime == "rust-cargo" and (
            name in RUST_RESERVED_ENVIRONMENT
            or name.startswith("CARGO_")
            or name.startswith("RUST")
            or name.startswith("LD_")
            or name.startswith("DYLD_")
        ):
            raise RunnerError("Rust subject environment cannot control the toolchain")
        environment[name] = value
    if args.subject_runtime == "rust-cargo":
        environment = {**environment, **RUST_FIXED_ENVIRONMENT}
    return list(raw_arguments), environment


def _rust_build(args: argparse.Namespace) -> dict[str, str] | None:
    value = _json_cli(args.rust_build_json, "Rust build contract")
    if args.subject_runtime != "rust-cargo":
        if value is not None:
            raise RunnerError("rust-build-json must be null for non-Rust subjects")
        return None
    if not isinstance(value, dict) or set(value) != RUST_BUILD_FIELDS:
        raise RunnerError("Rust build contract fields are invalid")
    if value.get("profile") != "rust-cargo-v1":
        raise RunnerError("Rust build profile is invalid")
    for field in ("manifest_sha256", "lock_sha256", "runtime_manifest_sha256"):
        if (
            not isinstance(value.get(field), str)
            or DIGEST.fullmatch(value[field]) is None
        ):
            raise RunnerError(f"Rust build {field.replace('_', '-')} is invalid")
    manifest = _safe_path(str(value.get("manifest_path", "")), "Rust manifest path")
    lock = _safe_path(str(value.get("lock_path", "")), "Rust lock path")
    if not str(value["manifest_path"]).startswith(".github/feature-regression/"):
        raise RunnerError("Rust manifest must use the reserved governance path")
    if manifest.name != "Cargo.toml" or lock != manifest.parent / "Cargo.lock":
        raise RunnerError("Rust lock must be the manifest's sibling Cargo.lock")
    _verify_file(manifest, value["manifest_sha256"], "Rust manifest")
    _verify_file(lock, value["lock_sha256"], "Rust lock")
    try:
        manifest_document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerError(f"Rust manifest is invalid TOML: {error}") from error
    binaries = manifest_document.get("bin")
    if (
        not isinstance(binaries, list)
        or len(binaries) != 1
        or not isinstance(binaries[0], dict)
        or binaries[0].get("name") != "elevenid-feature-regression-probe"
        or not isinstance(binaries[0].get("path"), str)
    ):
        raise RunnerError("Rust manifest must declare the one fixed probe binary")
    binary_path = _safe_path(
        pathlib.PurePosixPath(value["manifest_path"])
        .parent.joinpath(binaries[0]["path"])
        .as_posix(),
        "Rust probe binary path",
    )
    subject = _safe_path(args.subject_path, "subject-path")
    if binary_path != subject:
        raise RunnerError("Rust manifest binary path must identify the subject")
    approved_manifest = APPROVED_RUST_RUNTIME_IMAGES.get(args.runtime_image)
    if approved_manifest != value["runtime_manifest_sha256"]:
        raise RunnerError("Rust runtime image is not activated by central policy")
    return {key: str(value[key]) for key in sorted(RUST_BUILD_FIELDS)}


def _subject_command(
    *,
    runtime: str,
    subject_path: str,
    arguments: list[str],
    rust_build: dict[str, str] | None,
) -> list[str]:
    container_subject = f"/workspace/{pathlib.PurePosixPath(subject_path).as_posix()}"
    if runtime == "python":
        return ["python3", container_subject, *arguments]
    if runtime == "direct":
        return [container_subject, *arguments]
    if runtime == "rust-cargo" and rust_build is not None:
        return [
            "/opt/elevenid/bin/run-rust-probe",
            f"/workspace/{rust_build['manifest_path']}",
            f"/workspace/{rust_build['lock_path']}",
            container_subject,
            *arguments,
        ]
    raise RunnerError("subject runtime must be python, direct, or rust-cargo")


def _bounded_reader(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    exceeded: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    while True:
        chunk = stream.read(65_536)
        if not chunk:
            return
        remaining = limit + 1 - len(destination)
        if remaining > 0:
            destination.extend(chunk[:remaining])
        if len(destination) > limit:
            exceeded.set()
            _terminate_process_tree(process)
            return


def _stdin_writer(stream: BinaryIO, content: bytes) -> None:
    try:
        stream.write(content)
        stream.flush()
    except BrokenPipeError:
        pass
    finally:
        stream.close()


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif os.name == "nt":
        system_root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        taskkill = system_root / "System32" / "taskkill.exe"
        if taskkill.is_file():
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            process.kill()


def _run_process(
    command: list[str],
    environment: dict[str, str],
    *,
    label: str,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    stdin_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    group_options: dict[str, Any] = {}
    if os.name == "posix":
        group_options["start_new_session"] = True
    elif os.name == "nt":
        group_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=environment,
        cwd=pathlib.Path.cwd(),
        **group_options,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(process)
        raise RunnerError(f"{label} process pipes were not created")
    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    readers = (
        threading.Thread(
            target=_bounded_reader,
            args=(process.stdout, stdout, stdout_limit, exceeded, process),
            daemon=True,
        ),
        threading.Thread(
            target=_bounded_reader,
            args=(process.stderr, stderr, stderr_limit, exceeded, process),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    writer: threading.Thread | None = None
    if stdin_data is not None:
        if process.stdin is None:
            _terminate_process_tree(process)
            raise RunnerError(f"{label} process stdin pipe was not created")
        writer = threading.Thread(
            target=_stdin_writer,
            args=(process.stdin, stdin_data),
            daemon=True,
        )
        writer.start()
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        return_code = -1
    finally:
        _terminate_process_tree(process)
        if process.poll() is None:
            process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise RunnerError(f"{label} descendants retained process output pipes")
        if writer is not None and writer.is_alive():
            raise RunnerError(f"{label} retained the process input pipe")
        process.stdout.close()
        process.stderr.close()
    if timed_out:
        raise RunnerError(f"{label} invocation timed out")
    if exceeded.is_set():
        raise RunnerError(f"{label} output exceeded the configured bound")
    if return_code != 0:
        raise RunnerError(f"{label} invocation exited with status {return_code}")
    return bytes(stdout), bytes(stderr)


def _docker_binary() -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise RunnerError("docker is required for isolated behavior observation")
    return executable


def _container_command(
    *,
    docker: str,
    image: str,
    name: str,
    workload: list[str],
    environment: dict[str, str],
    profile: str = "standard-v1",
) -> list[str]:
    workspace = pathlib.Path.cwd().resolve()
    if "," in str(workspace):
        raise RunnerError("workspace path cannot contain a comma")
    command = [
        docker,
        "run",
        "--rm",
        "--interactive",
        "--pull=never",
        f"--name={name}",
        "--init",
        "--network=none",
        "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        "--ulimit=nofile=256:256",
        "--ulimit=core=0:0",
        "--user=65534:65534",
        "--mount",
        f"type=bind,source={workspace},target=/workspace,readonly",
        "--workdir=/workspace",
    ]
    if profile == "standard-v1":
        command.extend(
            ("--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1")
        )
    elif profile == "rust-cargo-v1":
        command.extend(
            (
                "--pids-limit=128",
                "--memory=4g",
                "--memory-swap=4g",
                "--cpus=2",
                "--tmpfs=/build:rw,exec,nosuid,nodev,size=2g,mode=0700,uid=65534,gid=65534",
                "--workdir=/build",
            )
        )
    else:
        raise RunnerError("container isolation profile is invalid")
    for name_, value in sorted(environment.items()):
        command.append(f"--env={name_}={value}")
    return [*command, image, *workload]


def _prepare_runtime_image(docker: str, image: str) -> str:
    _run_process(
        [docker, "pull", image],
        os.environ.copy(),
        label="runtime image pull",
        timeout=300,
        stdout_limit=65_536,
        stderr_limit=65_536,
    )
    stdout, _ = _run_process(
        [docker, "image", "inspect", "--format", "{{json .RepoDigests}}", image],
        os.environ.copy(),
        label="runtime image inspection",
        timeout=30,
        stdout_limit=65_536,
        stderr_limit=65_536,
    )
    digests = _parse_json(stdout.strip(), "runtime image repository digests")
    expected_digest = image.rsplit("@", 1)[1]
    if not isinstance(digests, list) or not any(
        isinstance(item, str) and item.endswith(f"@{expected_digest}")
        for item in digests
    ):
        raise RunnerError("local runtime image does not match the requested digest")
    return expected_digest


def _remove_container(docker: str, name: str) -> None:
    try:
        result = subprocess.run(
            [docker, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=os.environ.copy(),
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError("failed to terminate the isolated container") from error
    if result.returncode != 0 and b"No such container" not in result.stderr:
        raise RunnerError("failed to terminate the isolated container")


def _run_container(
    args: argparse.Namespace,
    workload: list[str],
    environment: dict[str, str],
    *,
    label: str,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    stdin_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    docker = _docker_binary()
    name = f"elevenid-feature-review-{secrets.token_hex(12)}"
    command = _container_command(
        docker=docker,
        image=args.runtime_image,
        name=name,
        workload=workload,
        environment=environment,
        profile=(
            "rust-cargo-v1"
            if args.subject_runtime == "rust-cargo" and label == "subject"
            else "standard-v1"
        ),
    )
    try:
        return _run_process(
            command,
            os.environ.copy(),
            label=label,
            timeout=timeout,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            stdin_data=stdin_data,
        )
    finally:
        _remove_container(docker, name)


def _runtime_manifest(
    args: argparse.Namespace, rust_build: dict[str, str]
) -> dict[str, str]:
    content, _ = _run_container(
        args,
        ["/bin/cat", "/opt/elevenid/runtime-manifest.json"],
        FIXED_ENVIRONMENT,
        label="Rust runtime manifest",
        timeout=30,
        stdout_limit=65_536,
        stderr_limit=65_536,
    )
    if (
        f"sha256:{hashlib.sha256(content).hexdigest()}"
        != rust_build["runtime_manifest_sha256"]
    ):
        raise RunnerError("Rust runtime manifest digest does not match")
    manifest = _parse_json(content, "Rust runtime manifest")
    expected_fields = {
        "schema",
        "profile",
        "rustc_version",
        "cargo_version",
        "python_version",
        "vendor_lock_sha256",
        "wrapper_sha256",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_fields
        or manifest.get("schema") != "elevenid.rust-cargo-runtime/v1"
        or manifest.get("profile") != "rust-cargo-v1"
        or manifest.get("vendor_lock_sha256") != rust_build["lock_sha256"]
        or DIGEST.fullmatch(str(manifest.get("wrapper_sha256"))) is None
        or any(
            not isinstance(manifest.get(field), str) or not manifest[field]
            for field in ("rustc_version", "cargo_version", "python_version")
        )
    ):
        raise RunnerError("Rust runtime manifest fields are invalid")
    if content != _canonical(manifest):
        raise RunnerError("Rust runtime manifest must be canonical JSON")
    return {key: str(manifest[key]) for key in sorted(expected_fields)}


def _validate_subject_output(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or set(document) != {"schema", "observations"}:
        raise RunnerError("subject output fields do not match the schema")
    if document.get("schema") != "elevenid.behavior-subject-output/v2":
        raise RunnerError("subject output schema is invalid")
    observations = document.get("observations")
    if not isinstance(observations, list) or not observations:
        raise RunnerError("subject observations must be a non-empty array")
    ids: set[str] = set()
    identities: set[tuple[Any, Any, Any]] = set()
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != {
            "id",
            "operation_id",
            "case_id",
            "dimension",
            "value",
        }:
            raise RunnerError(f"subject observation {index} fields are invalid")
        observation_id = observation.get("id")
        identity = (
            observation.get("operation_id"),
            observation.get("case_id"),
            observation.get("dimension"),
        )
        if (
            not isinstance(observation_id, str)
            or not observation_id
            or observation_id in ids
            or identity in identities
            or observation.get("dimension") not in DIMENSIONS
        ):
            raise RunnerError(f"subject observation {index} identity is invalid")
        ids.add(observation_id)
        identities.add(identity)
    return observations


def _capture_document(
    args: argparse.Namespace,
    *,
    observations: list[dict[str, Any]],
    arguments: list[str],
    environment: dict[str, str],
    stdout: bytes,
    stderr: bytes,
    rust_build: dict[str, str] | None,
    resolved_image_digest: str,
    runtime_manifest: dict[str, str] | None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "arguments": arguments,
        "environment": environment,
        "exit_code": 0,
        "runtime": args.subject_runtime,
        "runtime_image": args.runtime_image,
        "stderr_sha256": f"sha256:{hashlib.sha256(stderr).hexdigest()}",
        "stdout_sha256": f"sha256:{hashlib.sha256(stdout).hexdigest()}",
        "subject_path": args.subject_path,
        "subject_sha256": args.subject_sha256,
    }
    if rust_build is not None:
        receipt["resolved_image_digest"] = resolved_image_digest
        receipt["rust_build"] = rust_build
        receipt["runtime_manifest"] = runtime_manifest
    return {
        "schema": "elevenid.behavior-subject-capture/v2",
        "receipt": receipt,
        "observations": observations,
    }


def _validate_observations(
    document: Any,
    *,
    repository: str,
    revision: str,
    phase: str,
    final: bool,
    capture: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise RunnerError("observation document must be an object")
    expected_fields = {"schema", "repository", "revision", "phase", "observations"}
    if final:
        expected_fields.update({"producer", "runtime_receipt"})
    if set(document) != expected_fields:
        raise RunnerError("observation document fields do not match the schema")
    expected_schema = (
        "elevenid.behavior-observations/v3"
        if final
        else "elevenid.behavior-observations-runtime/v2"
    )
    if document.get("schema") != expected_schema:
        raise RunnerError("observation schema does not match the production phase")
    if (
        document.get("repository") != repository
        or document.get("revision") != revision
        or document.get("phase") != phase
    ):
        raise RunnerError("observation repository/revision/phase does not match")
    observations = document.get("observations")
    if not isinstance(observations, list) or not observations:
        raise RunnerError("observations must be a non-empty array")
    captured_by_identity = {
        (
            observation["operation_id"],
            observation["case_id"],
            observation["dimension"],
        ): observation
        for observation in capture["observations"]
    }
    if len(observations) != len(captured_by_identity):
        raise RunnerError(
            "harness observations do not cover the captured subject output"
        )
    seen: set[str] = set()
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != {
            "id",
            "operation_id",
            "case_id",
            "dimension",
            "value",
            "producer_test",
        }:
            raise RunnerError(f"observation {index} fields do not match the schema")
        observation_id = observation.get("id")
        identity = (
            observation.get("operation_id"),
            observation.get("case_id"),
            observation.get("dimension"),
        )
        captured = captured_by_identity.get(identity)
        expected_id = f"{identity[1]}.{identity[2]}.{phase}"
        if captured is None or observation_id != expected_id or observation_id in seen:
            raise RunnerError(
                "observation ids must exactly match captured subject output"
            )
        seen.add(observation_id)
        actual_core = {
            key: observation[key]
            for key in ("operation_id", "case_id", "dimension", "value")
        }
        captured_core = {
            key: captured[key]
            for key in ("operation_id", "case_id", "dimension", "value")
        }
        if _canonical(actual_core) != _canonical(captured_core):
            raise RunnerError(
                "harness observation differs from captured subject output"
            )
        reference = observation.get("producer_test")
        match = (
            TEST_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
        )
        if (
            match is None
            or match.group("repository").casefold() != repository.casefold()
            or match.group("commit") != revision
        ):
            raise RunnerError(
                f"observation {observation_id} producer_test must bind the target revision"
            )
    if final and document.get("runtime_receipt") != capture["receipt"]:
        raise RunnerError(
            "runtime receipt does not match the runner-owned subject capture"
        )
    return document


def _producer(
    args: argparse.Namespace, rust_build: dict[str, str] | None
) -> dict[str, Any]:
    workflow_path = _safe_path(args.workflow_path, "workflow-path")
    producer = {
        "workflow_path": args.workflow_path,
        "workflow_sha256": _file_digest(workflow_path, "producer workflow"),
        "central_workflow_sha": args.policy_ref,
        "harness_path": args.harness_path,
        "harness_sha256": args.harness_sha256,
        "subject_path": args.subject_path,
        "subject_sha256": args.subject_sha256,
        "subject_runtime": args.subject_runtime,
        "subject_args": _json_cli(args.subject_args_json, "subject args"),
        "subject_env": _json_cli(args.subject_env_json, "subject environment"),
        "runtime_image": args.runtime_image,
        "job_name": args.job_name,
        "artifact_name": args.artifact_name,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "head_sha": args.revision,
        "phase": args.phase,
        "event_name": args.event_name,
        "head_branch": args.head_branch,
    }
    if rust_build is not None:
        producer["rust_build"] = rust_build
    return producer


def _fsync_directory(path: pathlib.Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in {errno.EBADF, errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(descriptor)


def _atomic_write(output: pathlib.Path, content: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = pathlib.Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if output.exists() or output.is_symlink():
            raise RunnerError("observation output appeared before atomic publication")
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise RunnerError(
                "observation output appeared before atomic publication"
            ) from error
        published = True
    finally:
        if temporary.exists():
            temporary.unlink()
        if published:
            _fsync_directory(output.parent)


def _produce(args: argparse.Namespace) -> None:
    harness = _safe_path(args.harness_path, "harness-path")
    subject = _safe_path(args.subject_path, "subject-path")
    output = _safe_path(args.output, "output")
    if output.exists() or output.is_symlink():
        raise RunnerError("stale observation output exists before production")
    _verify_file(harness, args.harness_sha256, "observation harness")
    _verify_file(subject, args.subject_sha256, "observation subject")
    rust_build = _rust_build(args)
    resolved_image_digest = _prepare_runtime_image(_docker_binary(), args.runtime_image)
    runtime_manifest = (
        _runtime_manifest(args, rust_build) if rust_build is not None else None
    )
    arguments, environment = _subject_spec(args)
    subject_command = _subject_command(
        runtime=args.subject_runtime,
        subject_path=args.subject_path,
        arguments=arguments,
        rust_build=rust_build,
    )
    stdout, stderr = _run_container(
        args,
        subject_command,
        environment,
        label="subject",
        timeout=(
            RUST_SUBJECT_TIMEOUT_SECONDS
            if rust_build is not None
            else SUBJECT_TIMEOUT_SECONDS
        ),
        stdout_limit=MAX_SUBJECT_STDOUT,
        stderr_limit=MAX_SUBJECT_STDERR,
    )
    _verify_file(subject, args.subject_sha256, "observation subject")
    _verify_file(harness, args.harness_sha256, "observation harness")
    if rust_build is not None:
        _verify_file(
            _safe_path(rust_build["manifest_path"], "Rust manifest path"),
            rust_build["manifest_sha256"],
            "Rust manifest",
        )
        _verify_file(
            _safe_path(rust_build["lock_path"], "Rust lock path"),
            rust_build["lock_sha256"],
            "Rust lock",
        )
    subject_document = _parse_json(stdout, "subject output")
    if stdout != _canonical(subject_document):
        raise RunnerError("subject output must be canonical JSON")
    capture = _capture_document(
        args,
        observations=_validate_subject_output(subject_document),
        arguments=arguments,
        environment=environment,
        stdout=stdout,
        stderr=stderr,
        rust_build=rust_build,
        resolved_image_digest=resolved_image_digest,
        runtime_manifest=runtime_manifest,
    )
    capture_content = _canonical(capture)

    revalidated_output = _safe_path(args.output, "output")
    if revalidated_output != output:
        raise RunnerError("observation output path changed during subject execution")
    output = revalidated_output
    _run_container(
        args,
        [
            "python3",
            f"/workspace/{args.harness_path}",
            "test",
            "--phase",
            args.phase,
        ],
        FIXED_ENVIRONMENT,
        label="harness test",
        timeout=HARNESS_TIMEOUT_SECONDS,
        stdout_limit=MAX_HARNESS_STDOUT,
        stderr_limit=MAX_HARNESS_STDERR,
        stdin_data=capture_content,
    )
    _verify_file(harness, args.harness_sha256, "observation harness")
    harness_output, _ = _run_container(
        args,
        [
            "python3",
            f"/workspace/{args.harness_path}",
            "emit",
            "--repository",
            args.repository,
            "--revision",
            args.revision,
            "--phase",
            args.phase,
        ],
        FIXED_ENVIRONMENT,
        label="harness emit",
        timeout=HARNESS_TIMEOUT_SECONDS,
        stdout_limit=MAX_HARNESS_OBSERVATION_BYTES,
        stderr_limit=MAX_HARNESS_STDERR,
        stdin_data=capture_content,
    )
    _verify_file(harness, args.harness_sha256, "observation harness")
    runtime = _validate_observations(
        _parse_json(harness_output, "runtime observation"),
        repository=args.repository,
        revision=args.revision,
        phase=args.phase,
        final=False,
        capture=capture,
    )

    final = dict(runtime)
    final["schema"] = "elevenid.behavior-observations/v3"
    final["runtime_receipt"] = capture["receipt"]
    final["producer"] = _producer(args, rust_build)
    _validate_observations(
        final,
        repository=args.repository,
        revision=args.revision,
        phase=args.phase,
        final=True,
        capture=capture,
    )
    if _safe_path(args.output, "output") != output:
        raise RunnerError("observation output path changed during harness execution")
    _atomic_write(output, _canonical(final))


def _add_contract(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--harness-path", required=True)
    parser.add_argument("--harness-sha256", required=True)
    parser.add_argument("--subject-path", required=True)
    parser.add_argument("--subject-sha256", required=True)
    parser.add_argument("--subject-runtime", required=True)
    parser.add_argument("--subject-args-json", required=True)
    parser.add_argument("--subject-env-json", required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--rust-build-json", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--policy-ref", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)


def _validate_args(args: argparse.Namespace) -> None:
    if not SHA.fullmatch(args.revision):
        raise RunnerError("revision must be a full lowercase SHA")
    if args.phase not in {"before", "after"}:
        raise RunnerError("phase must be before or after")
    if args.phase == "after":
        if args.event_name != "pull_request":
            raise RunnerError("after observations require a pull_request event")
    elif (
        args.event_name not in {"push", "schedule", "workflow_dispatch"}
        or args.head_branch != "main"
    ):
        raise RunnerError(
            "before observations require push, schedule, or workflow_dispatch on main"
        )
    if not SHA.fullmatch(args.policy_ref):
        raise RunnerError("policy-ref must be a full lowercase SHA")
    if not REPOSITORY.fullmatch(args.repository):
        raise RunnerError("repository must be owner/repository")
    if OCI_IMAGE.fullmatch(args.runtime_image) is None:
        raise RunnerError("runtime-image must be pinned by sha256 digest")
    if args.subject_runtime not in {"python", "direct", "rust-cargo"}:
        raise RunnerError("subject-runtime is invalid")
    for field in ("harness_sha256", "subject_sha256"):
        if not DIGEST.fullmatch(getattr(args, field)):
            raise RunnerError(f"{field.replace('_', '-')} is invalid")
    for field in ("run_id", "run_attempt"):
        if getattr(args, field) <= 0:
            raise RunnerError(f"{field.replace('_', '-')} must be positive")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Atomically produce trusted behavior observations"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    produce = commands.add_parser("produce")
    _add_contract(produce)
    args = parser.parse_args(argv)
    try:
        _validate_args(args)
        _produce(args)
        return 0
    except (OSError, RunnerError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
