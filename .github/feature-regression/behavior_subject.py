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
DEPENDENCY_MANIFEST_SHA256 = "23ac0f2baf1cf33ba59deb277414b9db0bec82365c3009b26ea9bae7d12b6acb"
SCRIPT_NAMES = {
    "dependency_health.py", "feature_regression_observation_runner.py",
    "feature_regression_review.py", "prune_local_evidence.py",
    "rust_runtime_bundle.py", "rust_runtime_publication.py",
    "rust_runtime_registry.py", "rust_runtime_source_access.py",
    "rust_runtime_source_fetch.py", "workflow_policy.py",
}


class ProductionOwnerAbsent(Exception):
    """The new production module does not exist at this exact revision."""


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
        path.name not in {"README.md", "action.yml", "audit.py", "private_forks_policy.py"}
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


def optional_production_module(name, relative):
    path = ROOT / relative
    if not path.exists() and not path.is_symlink():
        return None
    return production_module(name, relative)


def present_call(module, function):
    def run():
        if module is None:
            raise ProductionOwnerAbsent("production owner is absent at this revision")
        return function(module)
    return run


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

    def target_case(change=None):
        def run():
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = b'[[bin]]\nname = "elevenid-feature-regression-probe"\npath = "subject.rs"\n'
                paths = {
                    "manifest": ".github/feature-regression/probe/Cargo.toml",
                    "lock": ".github/feature-regression/probe/Cargo.lock",
                    "subject": ".github/feature-regression/probe/subject.rs",
                }
                content = {"manifest": manifest, "lock": b"# public fixture\n", "subject": b"fn main() {}\n"}
                target = dict(record)
                for name, relative in paths.items():
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content[name])
                    target[f"{name}_sha256"] = "sha256:" + hashlib.sha256(content[name]).hexdigest()
                if change == "digest":
                    target["subject_sha256"] = "sha256:" + "0" * 64
                if change == "binary":
                    path = root / paths["manifest"]
                    path.write_bytes(manifest.replace(b"subject.rs", b"other.rs"))
                    target["manifest_sha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                return bundle.verify_target(root, target)
        return run

    for name, change in [("target-valid", None), ("target-bad-digest", "digest"),
                         ("target-wrong-binary", "binary")]:
        case("runtime.bundle-target", name, target_case(change))

    case("runtime.bundle-output", "github-output-valid", lambda: bundle.github_output_bytes(record).decode("ascii"))
    case("runtime.bundle-output", "github-output-control-character",
         lambda: bundle.github_output_bytes({**record, "id": "public\nunsafe"}))

    def atomic_case(change=None):
        def run():
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "observations.json"
                if change == "existing":
                    output.write_bytes(b"prior evidence")
                if change == "symlink":
                    output.symlink_to(Path(directory) / "private-target")
                runner._atomic_write(output, b"public observation\n")
                return output.read_bytes().decode("ascii")
        return run

    for name, change in [("atomic-new", None), ("atomic-existing", "existing"),
                         ("atomic-symlink", "symlink")]:
        case("producer.atomic-output", name, atomic_case(change))

    def observation_case(change=None):
        observed = {"id": "public-status", "operation_id": "fixture.validation",
                    "case_id": "fixture", "dimension": "public_status", "value": "accepted"}
        document = {"schema": "elevenid.behavior-observations-runtime/v2",
                    "repository": "ElevenID/.github", "revision": "a" * 40,
                    "phase": "before", "observations": [{
                        **observed, "id": "fixture.public_status.before",
                        "producer_test": "test:ElevenID/.github@" + "a" * 40 + ":tests/test_policy_enrollment_subject.py::test_real_policy_runner_and_bundle_boundaries",
                    }]}
        if change == "value":
            document["observations"][0]["value"] = "forged"
        if change == "missing":
            document["observations"] = []
        if change == "phase":
            document["phase"] = "after"
        return lambda: runner._validate_observations(
            document, repository="ElevenID/.github", revision="a" * 40,
            phase="before", final=False, capture={"observations": [observed]},
        )

    for name, change in [("observation-valid", None), ("observation-forged-value", "value"),
                         ("observation-missing", "missing"), ("observation-wrong-phase", "phase")]:
        case("producer.observation-binding", name, observation_case(change))

    registry = optional_production_module("scripts.rust_runtime_registry", "scripts/rust_runtime_registry.py")
    access = optional_production_module("scripts.rust_runtime_source_access", "scripts/rust_runtime_source_access.py")
    fetch = optional_production_module("scripts.rust_runtime_source_fetch", "scripts/rust_runtime_source_fetch.py")

    case("restricted.registry-boundary", "registry-invalid-credential",
         present_call(registry, lambda module: module.require_private_package("invalid")))
    case("restricted.registry-boundary", "registry-untrusted-context",
         present_call(registry, lambda module: module.require_execution_context(
             repository="ElevenID/.github", revision="a" * 40,
             event_name="workflow_dispatch", environment={},
         )))

    local_lock = b'[[package]]\nname = "public-fixture"\nversion = "0.1.0"\n'
    unpinned_lock = local_lock + b'source = "git+https://github.com/ElevenID/example"\n'
    case("restricted.source-admission", "source-local-lock",
         present_call(access, lambda module: sorted(module.locked_git_sources(local_lock))))
    case("restricted.source-admission", "source-unpinned-git",
         present_call(access, lambda module: module.locked_git_sources(unpinned_lock)))
    case("restricted.source-admission", "source-empty-grants",
         present_call(access, lambda module: module.parse_grants(
             b'{"schema":"elevenid.rust-runtime-source-access/v1","grants":[]}')))
    case("restricted.source-admission", "source-duplicate-catalog-key",
         present_call(access, lambda module: module.parse_grants(
             b'{"schema":"a","schema":"b","grants":[]}')))
    case("restricted.source-admission", "source-unadmitted-candidate",
         present_call(access, lambda module: module.require_access(
             repository="ElevenID/example", revision="a" * 40,
             runtime_image="ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "b" * 64,
             runtime_manifest_sha256="sha256:" + "c" * 64,
             lock=local_lock, grants=[],
         )))

    case("restricted.source-fetch", "fetch-untrusted-context",
         present_call(fetch, lambda module: module.require_context({}, {})))
    case("restricted.source-fetch", "fetch-wrong-credential-host",
         present_call(fetch, lambda module: module.credential_response(
             "get", "protocol=https\nhost=unapproved.example\npath=ElevenID/ssi-elevenid\n", {},
         )))
    case("restricted.source-fetch", "fetch-missing-private-credential",
         present_call(fetch, lambda module: module.credential_response(
             "get", "protocol=https\nhost=github.com\npath=ElevenID/ssi-elevenid\n", {},
         )))

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
        except ProductionOwnerAbsent:
            values = {"public_status": "not_present", "public_message": None,
                      "safe_server_diagnostic": {"availability": "absent"}}
        except Exception as error:
            values = {"public_status": "rejected", "public_message": str(error),
                      "safe_server_diagnostic": {"exception": type(error).__name__}}
        for dimension, value in values.items():
            observations.append({"id": f"{name}.{dimension}", "operation_id": operation,
                                 "case_id": name, "dimension": dimension, "value": value})
    return {"schema": "elevenid.behavior-subject-output/v2", "observations": observations}


if __name__ == "__main__":
    sys.stdout.write(json.dumps(observe(), sort_keys=True, separators=(",", ":")))
