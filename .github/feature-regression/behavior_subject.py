"""Observe public policy functions; never fetch sources, credentials or images.

This is an enrollment implementation in progress. The catalog and independent
review must establish complete affected-surface coverage before enrollment.
"""

import sys

# The immutable subject must not import a candidate sibling named json.py (or
# another standard-library name) before it can validate its own dependencies.
sys.path[:] = [path for path in sys.path if path and path.startswith(sys.base_prefix)]
sys.dont_write_bytecode = True

import argparse  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
VENDOR = Path(__file__).resolve().parent / "vendor"
DEPENDENCY_MANIFEST_SHA256 = "97ad23048e430f54d7ae239d17ba0d57ed3195d8f5a982adb90baca527e3cdd9"
SCRIPT_NAMES = {
    "dependency_health.py", "feature_regression_observation_runner.py",
    "feature_regression_review.py", "prune_local_evidence.py",
    "rust_runtime_bundle.py", "rust_runtime_publication.py",
    "rust_runtime_registry.py", "rust_runtime_source_access.py",
    "rust_runtime_source_fetch.py", "workflow_policy.py",
}


def verified_dependencies():
    for path in (VENDOR, *VENDOR.parents):
        if path.is_symlink():
            raise ValueError("dependency ancestry contains a link")
    if {path.name for path in VENDOR.iterdir()} != {
        "yaml", "LICENSE.PyYAML", "pyyaml-source.json"
    }:
        raise ValueError("dependency import namespace changed")
    manifest = (VENDOR / "pyyaml-source.json").read_bytes()
    if hashlib.sha256(manifest).hexdigest() != DEPENDENCY_MANIFEST_SHA256:
        raise ValueError("dependency manifest changed")
    expected = json.loads(manifest)["files"]
    files = {}
    for path in VENDOR.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError("dependency contains a nonordinary input")
        if path.is_dir() and path != VENDOR / "yaml":
            raise ValueError("dependency cache or package namespace changed")
        if path.is_file() and path.name != "pyyaml-source.json":
            files[path.relative_to(VENDOR).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if files != expected:
        raise ValueError("dependency bytes changed")
    scripts = ROOT / "scripts"
    if scripts.is_symlink() or any(
        path.name not in SCRIPT_NAMES or path.is_symlink() or not path.is_file()
        for path in scripts.iterdir()
    ):
        raise ValueError("production script import namespace changed")
    action = ROOT / ".github/actions/open-source-audit"
    if action.is_symlink() or any(
        path.name not in {"action.yml", "audit.py", "private_forks_policy.py"}
        or path.is_symlink() or not path.is_file() for path in action.iterdir()
    ):
        raise ValueError("source policy import namespace changed")
    sys.path.insert(0, str(VENDOR))
    package = types.ModuleType("scripts")
    package.__path__ = [str(scripts)]
    sys.modules["scripts"] = package


def production_module(name, relative):
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("production owner is not an ordinary file")
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def probe_cases():
    verified_dependencies()
    policy = production_module("enrollment_source_policy", ".github/actions/open-source-audit/private_forks_policy.py")
    runner = production_module("scripts.feature_regression_observation_runner", "scripts/feature_regression_observation_runner.py")
    bundle = production_module("scripts.rust_runtime_bundle", "scripts/rust_runtime_bundle.py")
    cases = []

    def case(operation, name, function):
        cases.append((operation, name, function))

    def policy_call(text, repository="ElevenID/.github"):
        return lambda: policy.workflow_secret_findings(ROOT, text, repository)

    for name, text, repository in [
        ("public-workflow", "on: [pull_request]\njobs: {}\n", "ElevenID/.github"),
        ("fork-secret", "on: [pull_request]\njobs:\n  job:\n    env:\n      INPUT: ${{ secrets.UNRELATED }}\n", "ElevenID/.github"),
        ("duplicate-yaml", "on: [pull_request]\non: [push]\njobs: {}\n", "ElevenID/.github"),
        ("malformed-redaction", "on: [pull_request]\nname: [DIAGNOSTIC_SENTINEL_VALUE\n", "ElevenID/.github"),
        ("unknown-reader-repository", "on: [push]\njobs:\n  job:\n    env:\n      INPUT: ${{ secrets.PRIVATE_FORKS_READ_TOKEN }}\n", "Unapproved/example"),
        ("implicit-secret-inheritance", "on: [push]\njobs:\n  job:\n    secrets: inherit\n", "ElevenID/.github"),
    ]:
        case("policy.source-reader", name, policy_call(text, repository))

    for name, arguments, environment, runtime in [
        ("python-inputs", '["fixture"]', '{"PROBE_VALUE":"public"}', "python"),
        ("arguments-not-array", '{}', '{}', "python"),
        ("argument-control-character", '["line\\nnext"]', '{}', "python"),
        ("fixed-environment-override", '[]', '{"TZ":"changed"}', "python"),
        ("unsafe-environment-name", '[]', '{"lowercase":"changed"}', "python"),
        ("rust-toolchain-override", '[]', '{"RUSTFLAGS":"changed"}', "rust-cargo"),
    ]:
        args = argparse.Namespace(subject_args_json=arguments, subject_env_json=environment, subject_runtime=runtime)
        case("producer.subject-inputs", name, lambda args=args: runner._subject_spec(args))

    for name, contract in [("python-no-rust-build", "null"), ("python-rust-build-denied", "{}")]:
        args = argparse.Namespace(subject_runtime="python", rust_build_json=contract)
        case("producer.rust-build", name, lambda args=args: runner._rust_build(args))

    valid = {"schema": "elevenid.behavior-subject-output/v2", "observations": [{
        "id": "fixture.public_status", "operation_id": "fixture.validation",
        "case_id": "fixture", "dimension": "public_status", "value": "fixture-value",
    }]}
    for name, document in [
        ("subject-output", valid),
        ("subject-empty-output", {"schema": valid["schema"], "observations": []}),
        ("subject-duplicate-output", {**valid, "observations": valid["observations"] * 2}),
        ("subject-unknown-field", {**valid, "extra": True}),
    ]:
        case("producer.subject-output", name, lambda document=document: runner._validate_subject_output(document))

    def catalog_case(document, identity="public-probe"):
        def run():
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bundles.json"
                path.write_text(document, encoding="utf-8")
                return bundle.load_bundle(path, identity)
        return run

    record = {
        "id": "public-probe", "repository": "ElevenID/example", "revision": "a" * 40,
        "manifest_path": ".github/feature-regression/probe/Cargo.toml",
        "lock_path": ".github/feature-regression/probe/Cargo.lock",
        "subject_path": ".github/feature-regression/probe/subject.rs",
        "manifest_sha256": "sha256:" + "b" * 64,
        "lock_sha256": "sha256:" + "c" * 64,
        "subject_sha256": "sha256:" + "d" * 64,
    }
    for name, records in [
        ("bundle-valid", [record]), ("bundle-absent", []), ("bundle-duplicate", [record, record]),
        ("bundle-unsafe-path", [{**record, "manifest_path": "../Cargo.toml"}]),
        ("bundle-bad-digest", [{**record, "lock_sha256": "not-a-digest"}]),
    ]:
        document = json.dumps({"schema": "elevenid.rust-cargo-runtime-bundles/v1", "bundles": records})
        case("runtime.bundle-admission", name, catalog_case(document))
    case("runtime.bundle-admission", "bundle-duplicate-json-key", catalog_case('{"schema":"a","schema":"b","bundles":[]}'))

    return cases


def observe():
    observations = []
    for operation, name, function in probe_cases():
        try:
            result = function()
            # A policy findings list is itself the production diagnostic and
            # rejection decision, not a successful admission merely because the
            # Python function returned normally.
            rejected = operation == "policy.source-reader" and bool(result)
            values = {"public_status": "rejected" if rejected else "accepted",
                      "public_message": result if rejected else None,
                      "safe_server_diagnostic": {"returned": result}}
        except Exception as error:
            values = {"public_status": "rejected", "public_message": str(error),
                      "safe_server_diagnostic": {"exception": type(error).__name__}}
        for dimension, value in values.items():
            observations.append({"id": f"{name}.{dimension}", "operation_id": operation,
                                 "case_id": name, "dimension": dimension, "value": value})
    return {"schema": "elevenid.behavior-subject-output/v2", "observations": observations}


if __name__ == "__main__":
    sys.stdout.write(json.dumps(observe(), sort_keys=True, separators=(",", ":")))
