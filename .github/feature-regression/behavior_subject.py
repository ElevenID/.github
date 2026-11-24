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
import base64  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402
import zipfile  # noqa: E402


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


def available_function(module, name, function):
    def run():
        if not hasattr(module, name):
            raise ProductionOwnerAbsent("production function is absent at this revision")
        return function(getattr(module, name))
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

    publisher = ".github/workflows/publish-restricted-rust-probe-runtime.yml"

    def publisher_case(tamper=False):
        def run():
            path = ROOT / publisher
            if not path.exists() and not path.is_symlink():
                raise ProductionOwnerAbsent("restricted publisher does not exist at this revision")
            text = path.read_text(encoding="utf-8")
            if not tamper:
                return policy.workflow_secret_findings(ROOT, text, "ElevenID/.github", workflow_path=publisher)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative in policy.RESTRICTED_PUBLISHER_FILES:
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / relative).read_bytes())
                scripts = root / "scripts"
                for name in policy.RESTRICTED_SCRIPT_NAMES:
                    target = scripts / name
                    if not target.exists():
                        target.write_bytes((ROOT / "scripts" / name).read_bytes())
                with (root / "scripts/rust_runtime_source_fetch.py").open("ab") as stream:
                    stream.write(b"\n# public fixture tamper\n")
                return policy.workflow_secret_findings(root, text, "ElevenID/.github", workflow_path=publisher)
        return run

    case("policy.restricted-publisher", "restricted-publisher-valid", publisher_case())
    case("policy.restricted-publisher", "restricted-publisher-tampered-input", publisher_case(True))

    def producer_workflow_case(tamper=False):
        path = ROOT / ".github/workflows/feature-regression-observation-producer-restricted.yml"
        if not path.exists() and not path.is_symlink():
            raise ProductionOwnerAbsent("restricted observation producer is absent at this revision")
        raw = path.read_bytes().replace(b"\r\n", b"\n")
        if tamper:
            changed = raw.replace(b"actions: read", b"actions: write", 1)
            if changed == raw:
                raise ValueError("restricted producer permission fixture could not be changed")
            raw = changed
        digest = hashlib.sha256(raw).hexdigest()
        if digest != "9482f2e9ba9696de7ae671b5be038600b80bc67d91c1587c08a2e645c91c2f19":
            raise ValueError("restricted observation producer differs from reviewed public source")
        document = policy.yaml.load(raw.decode("utf-8"), Loader=policy.WorkflowLoader)
        event = document.get("on", {})
        permissions = document.get("permissions")
        secrets = event.get("workflow_call", {}).get("secrets", {}) if isinstance(event, dict) else None
        steps = document.get("jobs", {}).get("generate", {}).get("steps", [])
        produce = [step for step in steps if step.get("name") == "Produce trusted runtime observations atomically"]
        expected_secrets = {"RUST_RUNTIME_PACKAGE_READ_TOKEN", "RUST_RUNTIME_PACKAGE_USERNAME"}
        if (set(event) != {"workflow_call"}
                or permissions != {"actions": "read", "contents": "read"}
                or not isinstance(secrets, dict) or set(secrets) != expected_secrets
                or any(item.get("required") != "true" for item in secrets.values())
                or len(produce) != 1):
            raise ValueError("restricted observation producer workflow boundary changed")
        environment = produce[0].get("env", {})
        if (
            environment.get("RUST_RUNTIME_PULL_TOKEN") != "${{ secrets.RUST_RUNTIME_PACKAGE_READ_TOKEN }}"
            or environment.get("RUST_RUNTIME_REGISTRY_USERNAME") != "${{ secrets.RUST_RUNTIME_PACKAGE_USERNAME }}"
            or environment.get("GITHUB_TOKEN") != "${{ github.token }}"
        ):
            raise ValueError("restricted observation producer secret mapping changed")
        return {"sha256": digest, "permissions": permissions,
                "private_secret_names": sorted(expected_secrets)}

    case("policy.restricted-producer-source", "restricted-producer-valid", producer_workflow_case)
    case("policy.restricted-producer-source", "restricted-producer-permission-tamper",
         lambda: producer_workflow_case(True))

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

    # Read the protected repository catalog, not a synthetic fixture. The
    # current base has no such entry; a later admission changes this result.
    case("runtime.bundle-live", "live-auth-flow-bundle",
         lambda: bundle.load_bundle(ROOT / "runtime/rust-cargo/bundles.json",
                                    "marty-ui-auth-flow-20261124"))

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

    case("runtime.bundle-output", "github-output-valid",
         lambda: bundle.github_output_bytes(record).decode("ascii").splitlines())
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
                content = output.read_bytes()
                return {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
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

    def pull_environment_case():
        if "pull_environment" not in runner._prepare_runtime_image.__code__.co_varnames:
            raise ProductionOwnerAbsent("isolated runtime pull argument is absent at this revision")
        original = runner._run_process
        seen = []
        image = "node:24.15.0-bookworm@sha256:" + "a" * 64

        def public_process(command, environment, **arguments):
            seen.append((command[1], environment.get("DOCKER_CONFIG")))
            if command[1] == "pull":
                return b"", b""
            if command[1] == "image":
                return json.dumps([image]).encode(), b""
            raise ValueError("runtime pull fixture received an unexpected command")

        runner._run_process = public_process
        try:
            digest = runner._prepare_runtime_image(
                "docker", image, pull_environment={"DOCKER_CONFIG": "public-fixture-config"},
            )
        finally:
            runner._run_process = original
        if digest != "sha256:" + "a" * 64 or seen != [
            ("pull", "public-fixture-config"), ("image", None),
        ]:
            raise ValueError("runtime pull fixture crossed its credential boundary")
        return {"resolved_digest": digest, "pull_used_private_config": True,
                "inspection_excluded_private_config": True}

    case("producer.pull-isolation", "producer-isolated-runtime-pull", pull_environment_case)

    def admission_order_case():
        if not hasattr(runner, "source_access"):
            raise ProductionOwnerAbsent("restricted producer admission is absent at this revision")
        saved = (runner._verify_file, runner._rust_build, runner._docker_binary,
                 runner._prepare_runtime_image, runner.source_access.admit_from_protected_main)
        events = []

        def deny_admission(**arguments):
            events.append("source-admission")
            if arguments.get("token") != "publicfixture123" or "GITHUB_TOKEN" in os.environ:
                raise ValueError("producer credential fixture was not consumed safely")
            raise runner.source_access.SourceAccessError("public fixture denied")

        def forbidden_pull(*arguments, **keywords):
            events.append("pull-before-admission")
            raise ValueError("runtime pull preceded source admission")

        environment = {name: os.environ.get(name) for name in (
            "RUST_RUNTIME_PULL_TOKEN", "RUST_RUNTIME_REGISTRY_USERNAME", "GITHUB_TOKEN",
        )}
        for name in environment:
            os.environ[name] = "publicfixture123"
        runner._verify_file = lambda *arguments: None
        runner._rust_build = lambda arguments: {"lock_path": "runtime/rust-cargo/bundles.json",
                                                 "runtime_manifest_sha256": "sha256:" + "a" * 64}
        runner._docker_binary = forbidden_pull
        runner._prepare_runtime_image = forbidden_pull
        runner.source_access.admit_from_protected_main = deny_admission
        try:
            arguments = argparse.Namespace(
                harness_path=".github/feature-regression/observation_harness.py",
                subject_path=".github/feature-regression/behavior_subject.py",
                output="public-fixture-observations.json",
                runtime_image="ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "b" * 64,
                repository="ElevenID/example", revision="a" * 40, event_name="pull_request",
                harness_sha256="sha256:" + "a" * 64,
                subject_sha256="sha256:" + "a" * 64,
            )
            try:
                runner._produce(arguments)
            except runner.RunnerError as error:
                if str(error) != "public fixture denied":
                    raise
            else:
                raise ValueError("source admission denial was ignored")
            if events != ["source-admission"]:
                raise ValueError("producer attempted a pull before source admission")
            return {"events": events, "pull_before_admission": False}
        finally:
            (runner._verify_file, runner._rust_build, runner._docker_binary,
             runner._prepare_runtime_image, runner.source_access.admit_from_protected_main) = saved
            for name, value in environment.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    case("producer.admission-order", "producer-denied-before-pull", admission_order_case)

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

    def registry_pull_case(fail_login=False):
        def invoke(module):
            original_opener = module.urllib.request.build_opener
            original_environment = {name: os.environ.get(name) for name in (
                "RUST_RUNTIME_PULL_TOKEN", "PRIVATE_FORKS_READ_TOKEN", "GITHUB_TOKEN",
            )}
            events = []
            configs = []
            denials = []

            class DeniedOpener:
                def open(self, request, timeout):
                    denials.append(request.full_url.split("?", 1)[0])
                    raise module.urllib.error.HTTPError(
                        request.full_url, 401, "denied", {},
                        io.BytesIO(b'{"errors":[{"code":"DENIED"}]}'),
                    )

            def public_process(command, environment, **arguments):
                action = command[1]
                events.append(action)
                configs.append(Path(environment["DOCKER_CONFIG"]))
                if action == "login":
                    if arguments.get("stdin_data") != b"publicfixture123":
                        raise ValueError("registry fixture stdin was not bound")
                    if fail_login:
                        raise RuntimeError("controlled registry login failure")
                return b"", b""

            module.urllib.request.build_opener = lambda *args: DeniedOpener()
            for name in original_environment:
                os.environ[name] = "publicfixture123"
            try:
                try:
                    with module.private_pull_environment(
                        docker="docker", image=(
                            "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "a" * 64
                        ), token="publicfixture123", actor="public-actor",
                        run_process=public_process,
                    ) as environment:
                        if fail_login or any(name in environment for name in original_environment):
                            raise ValueError("registry fixture environment was not scoped")
                        if not Path(environment["DOCKER_CONFIG"]).is_dir():
                            raise ValueError("registry fixture config was not temporary")
                except RuntimeError:
                    if not fail_login:
                        raise
                if (events != ["login", "logout"] or any(path.exists() for path in configs)
                        or len(denials) != (1 if fail_login else 2)):
                    raise ValueError("registry fixture cleanup or anonymous refusal changed")
                return {"events": events, "anonymous_denials": len(denials),
                        "temporary_config_retired": True}
            finally:
                module.urllib.request.build_opener = original_opener
                for name, value in original_environment.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
        return present_call(registry, invoke)

    case("restricted.registry-boundary", "registry-pull-cleanup", registry_pull_case())
    case("restricted.registry-boundary", "registry-login-failure-cleanup", registry_pull_case(True))

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

    candidate = {
        "repository": "ElevenID/example", "revision": "a" * 40,
        "runtime_image": "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "b" * 64,
        "runtime_manifest_sha256": "sha256:" + "c" * 64,
        "lock": local_lock,
    }
    grant = {
        "repository": candidate["repository"], "revision": candidate["revision"],
        "runtime_image": candidate["runtime_image"],
        "runtime_manifest_sha256": candidate["runtime_manifest_sha256"],
        "lock_sha256": "sha256:" + hashlib.sha256(local_lock).hexdigest(),
        "git_sources": [],
    }

    def grant_catalog(grants):
        return json.dumps({"schema": "elevenid.rust-runtime-source-access/v1", "grants": grants},
                          sort_keys=True, separators=(",", ":")).encode()

    case("restricted.source-admission", "source-positive-grant",
         present_call(access, lambda module: module.require_access(
             **candidate, grants=module.parse_grants(grant_catalog([grant])),
         )))

    def checked_in_catalog_case(tamper=False):
        def invoke(module):
            path = ROOT / "runtime/rust-cargo/source-access.json"
            if not path.exists() and not path.is_symlink():
                raise ProductionOwnerAbsent("checked-in source-access catalog is absent at this revision")
            if tamper:
                with tempfile.TemporaryDirectory() as directory:
                    damaged = Path(directory) / "source-access.json"
                    damaged.write_bytes(b'{"schema":"invalid","grants":[]}')
                    return module.load_grants(damaged)
            grants = module.load_grants(path)
            return {"grant_count": len(grants), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return present_call(access, invoke)

    case("restricted.source-admission", "source-checked-in-catalog", checked_in_catalog_case())
    case("restricted.source-admission", "source-invalid-catalog", checked_in_catalog_case(True))

    def protected_case(revoked):
        def invoke(module):
            original = module._policy_api
            old = grant_catalog([grant])
            current = grant_catalog([]) if revoked else old
            old_revision, current_revision = "d" * 40, "e" * 40
            current_ref = current_revision if revoked else old_revision

            def catalog_response(raw):
                return {
                    "type": "file", "path": "runtime/rust-cargo/source-access.json",
                    "encoding": "base64", "content": base64.b64encode(raw).decode("ascii"),
                    "size": len(raw), "sha": hashlib.sha1(
                        b"blob " + str(len(raw)).encode() + b"\0" + raw,
                        usedforsecurity=False,
                    ).hexdigest(),
                }

            def public_fixture(path, token):
                if token:
                    raise ValueError("source-free fixture received a credential")
                if path == "git/ref/heads/main":
                    return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": current_ref}}
                if path == "contents/runtime/rust-cargo/source-access.json?ref=" + old_revision:
                    return catalog_response(old)
                if path == "contents/runtime/rust-cargo/source-access.json?ref=" + current_revision:
                    return catalog_response(current)
                if path == "compare/" + old_revision + "..." + current_revision:
                    return {"status": "ahead"}
                raise ValueError("source-free fixture received an unexpected request")

            proof = {
                "policy_repository": "ElevenID/.github", "policy_revision": old_revision,
                "catalog_sha256": "sha256:" + hashlib.sha256(old).hexdigest(),
                "grant_sha256": module.require_access(
                    **candidate, grants=module.parse_grants(old),
                ),
            }
            module._policy_api = public_fixture
            try:
                return module.verify_protected_admission(proof, token="", **candidate)
            finally:
                module._policy_api = original
                module._REMOTE_CATALOGS.pop(old_revision, None)
                module._REMOTE_CATALOGS.pop(current_revision, None)
        return present_call(access, invoke)

    case("restricted.source-admission", "source-protected-current", protected_case(False))
    case("restricted.source-admission", "source-protected-revoked", protected_case(True))

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

    reviewer = production_module("scripts.feature_regression_review", "scripts/feature_regression_review.py")
    publication = production_module("scripts.rust_runtime_publication", "scripts/rust_runtime_publication.py")

    def caller_case(restricted):
        rust_build = reviewer.RustBuildContract(
            profile="rust-cargo-v1",
            manifest_path=".github/feature-regression/probe/Cargo.toml",
            manifest_sha256="sha256:" + "1" * 64,
            lock_path=".github/feature-regression/probe/Cargo.lock",
            lock_sha256="sha256:" + "2" * 64,
            runtime_manifest_sha256="sha256:" + "3" * 64,
        ) if restricted else None
        contract = reviewer.ProducerContract(
            workflow_path=".github/workflows/behavior-observations.yml",
            workflow_sha256="sha256:" + "a" * 64,
            central_workflow_sha="b" * 40,
            harness_path=".github/feature-regression/observation_harness.py",
            harness_sha256="sha256:" + "c" * 64,
            subject_path=".github/feature-regression/behavior_subject.py",
            subject_sha256="sha256:" + "d" * 64,
            subject_runtime="rust-cargo" if restricted else "python",
            subject_args=(), subject_env={},
            runtime_image=(
                "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "e" * 64
                if restricted else "node:24.15.0-bookworm@sha256:" + "f" * 64
            ),
            rust_build=rust_build,
            job_name="behavior-observations / Behavior observation producer",
            produce_step_name="Produce trusted runtime observations atomically",
            upload_step_name="Upload runtime observations",
            artifact_name_prefix="feature-regression-observations",
            observation_path="feature-regression-observations.json",
        )
        content = reviewer._expected_producer_workflow(contract)
        return {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}

    case("reviewer.caller-selection", "reviewer-public-caller", lambda: caller_case(False))
    case("reviewer.caller-selection", "reviewer-restricted-caller", lambda: caller_case(True))

    def operation_identity_case(kind):
        evidence = ["artifact-observation:ElevenID/.github@123:fixture.public_status.before"]
        comparison = {
            "disposition": "preserved",
            "before": {"value": "accepted", "evidence": evidence},
            "after": {"value": "accepted", "evidence": evidence},
        }
        first = {
            "id": "fixture.operation", "case_id": "fixture.first",
            "name": "fixture operation", "public_status": comparison,
            "public_message": comparison, "safe_server_diagnostic": comparison,
        }
        second = {**first, "case_id": "fixture.second"}
        if kind == "duplicate-case":
            second = {**second, "case_id": first["case_id"]}
        elif kind == "name-id-conflict":
            second = {**second, "id": "fixture.other"}
        elif kind == "id-name-conflict":
            second = {**second, "name": "other fixture operation"}
        return reviewer._validate_operations(
            [first, second], reviewer_login="fixture", repository="ElevenID/.github",
            reviewed_base="a" * 40, allow_not_applicable=False,
            authority_resolver=lambda login: {"permission": "maintain", "role_name": "maintain"},
            decision_fetcher=lambda reference: b"{}",
        )

    for name, kind in (
        ("reviewer-multicase-valid", "valid"),
        ("reviewer-duplicate-case-id", "duplicate-case"),
        ("reviewer-name-id-conflict", "name-id-conflict"),
        ("reviewer-id-name-conflict", "id-name-conflict"),
    ):
        case("reviewer.operation-identity", name,
             lambda kind=kind: operation_identity_case(kind))

    def restricted_reviewer_contract():
        build = reviewer.RustBuildContract(
            profile="rust-cargo-v1", manifest_path=".github/feature-regression/probe/Cargo.toml",
            manifest_sha256="sha256:" + "1" * 64,
            lock_path=".github/feature-regression/probe/Cargo.lock",
            lock_sha256="sha256:" + "2" * 64,
            runtime_manifest_sha256="sha256:" + "3" * 64,
        )
        return reviewer.ProducerContract(
            workflow_path=".github/workflows/behavior-observations.yml",
            workflow_sha256="sha256:" + "4" * 64,
            central_workflow_sha="b" * 40,
            harness_path=".github/feature-regression/observation_harness.py",
            harness_sha256="sha256:" + "5" * 64,
            subject_path=".github/feature-regression/behavior_subject.py",
            subject_sha256="sha256:" + "6" * 64,
            subject_runtime="rust-cargo", subject_args=(), subject_env={},
            runtime_image="ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "7" * 64,
            rust_build=build,
            job_name="behavior-observations / Behavior observation producer",
            produce_step_name="Produce trusted runtime observations atomically",
            upload_step_name="Upload runtime observations",
            artifact_name_prefix="feature-regression-observations",
            observation_path="feature-regression-observations.json",
        )

    def reviewer_admission_case():
        if not hasattr(reviewer, "source_access"):
            raise ProductionOwnerAbsent("restricted reviewer admission is absent at this revision")
        original = reviewer.source_access.admit_from_protected_main
        events = []

        def lock_source(repository, path, commit):
            events.append("public-lock")
            if (repository, path, commit) != (
                "ElevenID/.github", ".github/feature-regression/probe/Cargo.lock", "a" * 40,
            ):
                raise ValueError("reviewer requested an unexpected source")
            return b"public fixture lock"

        def deny_admission(**arguments):
            events.append("source-admission")
            raise reviewer.source_access.SourceAccessError("public fixture denied")

        def forbid_artifact(*arguments, **keywords):
            events.append("artifact-fetched")
            raise ValueError("reviewer fetched an artifact before admission")

        reviewer.source_access.admit_from_protected_main = deny_admission
        try:
            try:
                reviewer._validate_artifact_observation(
                    "artifact-observation:ElevenID/.github@123:fixture.public_status.before",
                    "public fixture", expected_repository="ElevenID/.github",
                    expected_commit="a" * 40, expected_phase="before",
                    producer=restricted_reviewer_contract(),
                    operation_id="fixture.validation", case_id="fixture",
                    dimension="public_status", expected_value="accepted",
                    fetch_content=lock_source, fetch_run=forbid_artifact,
                    fetch_jobs=forbid_artifact, fetch_artifacts=forbid_artifact,
                    download_artifact=forbid_artifact,
                )
            except reviewer.EvidenceError as error:
                if str(error) != "public fixture denied":
                    raise
            else:
                raise ValueError("reviewer ignored protected source denial")
            if events != ["public-lock", "source-admission"]:
                raise ValueError("reviewer fetched an artifact before protected source admission")
            return {"events": events, "artifact_fetched": False}
        finally:
            reviewer.source_access.admit_from_protected_main = original

    case("reviewer.restricted-admission", "reviewer-denied-before-artifact", reviewer_admission_case)

    def reviewer_receipt_case():
        contract = restricted_reviewer_contract()
        image = contract.runtime_image
        receipt = {
            "runtime_image": image,
            "subject_path": contract.subject_path,
            "subject_sha256": contract.subject_sha256,
            "runtime": "rust-cargo", "arguments": [], "environment": {}, "exit_code": 0,
            "stdout_sha256": "sha256:" + "8" * 64,
            "stderr_sha256": "sha256:" + "9" * 64,
            "resolved_image_digest": image.rsplit("@", 1)[1],
            "rust_build": contract.rust_build.document(),
            "runtime_manifest": {name: "public-fixture" for name in reviewer.RUST_RUNTIME_MANIFEST_FIELDS},
        }
        observed = {
            "id": "fixture.public_status.before", "operation_id": "fixture.validation",
            "case_id": "fixture", "dimension": "public_status", "value": "accepted",
            "producer_test": "test:ElevenID/.github@" + "a" * 40
            + ":tests/test_policy_enrollment_subject.py::test_real_policy_runner_and_bundle_boundaries",
        }
        document = {
            "schema": "elevenid.behavior-observations/v3", "repository": "ElevenID/.github",
            "revision": "a" * 40, "phase": "before", "producer": {},
            "runtime_receipt": receipt, "observations": [observed],
        }
        return reviewer._select_observation(
            document, path="public fixture", observation_id=observed["id"],
            expected_repository="ElevenID/.github", expected_revision="a" * 40,
            expected_phase="before", operation_id="fixture.validation",
            case_id="fixture", dimension="public_status", expected_value="accepted",
            record_fields=set(observed),
        )

    case("reviewer.restricted-admission", "reviewer-missing-source-receipt", reviewer_receipt_case)

    def reviewer_late_proof_case():
        if not hasattr(reviewer, "source_access"):
            raise ProductionOwnerAbsent("restricted reviewer proof is absent at this revision")
        contract = restricted_reviewer_contract()
        commit = "a" * 40
        run_id = 123
        attempt = 1
        name = f"{contract.artifact_name_prefix}-{run_id}-{attempt}"
        observation = {
            "id": "fixture.public_status.before", "operation_id": "fixture.validation",
            "case_id": "fixture", "dimension": "public_status", "value": "accepted",
            "producer_test": f"test:ElevenID/.github@{commit}:tests/test_policy_enrollment_subject.py::test_real_policy_runner_and_bundle_boundaries",
        }
        document = {
            "schema": "elevenid.behavior-observations/v3", "repository": "ElevenID/.github",
            "revision": commit, "phase": "before", "observations": [observation],
            "producer": {
                "workflow_path": contract.workflow_path,
                "workflow_sha256": contract.workflow_sha256,
                "central_workflow_sha": contract.central_workflow_sha,
                "harness_path": contract.harness_path,
                "harness_sha256": contract.harness_sha256,
                "subject_path": contract.subject_path,
                "subject_sha256": contract.subject_sha256,
                "subject_runtime": contract.subject_runtime,
                "subject_args": [], "subject_env": {},
                "runtime_image": contract.runtime_image,
                "rust_build": contract.rust_build.document(),
                "job_name": contract.job_name, "artifact_name": name,
                "run_id": run_id, "run_attempt": attempt, "head_sha": commit,
                "phase": "before", "event_name": "push", "head_branch": "main",
            },
            "runtime_receipt": {
                "runtime_image": contract.runtime_image,
                "subject_path": contract.subject_path,
                "subject_sha256": contract.subject_sha256,
                "runtime": "rust-cargo", "arguments": [],
                "environment": {
                    "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0", "TZ": "UTC",
                    "CARGO_HOME": "/build/cargo-home", "CARGO_NET_OFFLINE": "true",
                    "CARGO_TARGET_DIR": "/build/target", "HOME": "/build/home",
                    "PATH": "/opt/elevenid/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
                    "RUSTUP_HOME": "/usr/local/rustup", "TMPDIR": "/tmp",
                },
                "exit_code": 0,
                "stdout_sha256": "sha256:" + "8" * 64,
                "stderr_sha256": "sha256:" + "9" * 64,
                "resolved_image_digest": contract.runtime_image.rsplit("@", 1)[1],
                "rust_build": contract.rust_build.document(),
                "source_access": {"public_fixture": "revoked"},
                "runtime_manifest": {},
            },
        }
        payload = reviewer._deterministic_json_bytes(document)
        archive_stream = io.BytesIO()
        with zipfile.ZipFile(archive_stream, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(contract.observation_path, payload)
        archive = archive_stream.getvalue()
        events = []

        def lock_source(repository, path, revision):
            events.append("public-lock")
            if (repository, path, revision) != (
                "ElevenID/.github", contract.rust_build.lock_path, commit,
            ):
                raise ValueError("unexpected proof source")
            return b"public fixture lock"

        def admit(**arguments):
            events.append("source-admission")
            return {"public_fixture": "admitted"}

        def revoke(receipt, **arguments):
            events.append("source-proof")
            raise reviewer.source_access.SourceAccessError("public fixture late proof revoked")

        def run(repository, requested_id):
            events.append("run")
            return {
                "status": "completed", "conclusion": "success", "head_sha": commit,
                "event": "push", "head_branch": "main", "run_attempt": attempt,
                "path": contract.workflow_path + "@refs/heads/main",
                "repository": {"id": 9}, "head_repository": {"id": 9},
            }

        def jobs(repository, requested_id, requested_attempt):
            events.append("jobs")
            return [{"name": contract.job_name, "status": "completed",
                     "conclusion": "success", "run_id": run_id, "head_sha": commit,
                     "steps": [{"name": step, "status": "completed", "conclusion": "success"}
                               for step in (contract.produce_step_name, contract.upload_step_name)]}]

        def artifacts(repository, requested_id):
            events.append("artifacts")
            return [{"name": name, "id": 5, "expired": False,
                     "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                     "workflow_run": {"id": run_id, "head_sha": commit,
                                      "head_branch": "main", "repository_id": 9,
                                      "head_repository_id": 9}}]

        def download(repository, artifact_id):
            events.append("download")
            return archive

        original_admit = reviewer.source_access.admit_from_protected_main
        original_verify = reviewer.source_access.verify_protected_admission
        reviewer.source_access.admit_from_protected_main = admit
        reviewer.source_access.verify_protected_admission = revoke
        try:
            try:
                reviewer._validate_artifact_observation(
                    f"artifact-observation:ElevenID/.github@{run_id}:{observation['id']}",
                    "public fixture", expected_repository="ElevenID/.github",
                    expected_commit=commit, expected_phase="before", producer=contract,
                    operation_id="fixture.validation", case_id="fixture",
                    dimension="public_status", expected_value="accepted",
                    fetch_content=lock_source, fetch_run=run, fetch_jobs=jobs,
                    fetch_artifacts=artifacts, download_artifact=download,
                )
            except reviewer.EvidenceError as error:
                if str(error) != "public fixture late proof revoked":
                    raise
            else:
                raise ValueError("reviewer ignored late protected source revocation")
            if events != ["public-lock", "source-admission", "run", "jobs",
                          "artifacts", "download", "public-lock", "source-proof"]:
                raise ValueError("reviewer did not verify protected source after artifact receipt")
            return {"events": events, "late_proof_rejected": True}
        finally:
            reviewer.source_access.admit_from_protected_main = original_admit
            reviewer.source_access.verify_protected_admission = original_verify

    case("reviewer.restricted-admission", "reviewer-revoked-late-proof", reviewer_late_proof_case)

    public_image = "ghcr.io/elevenid/feature-regression-rust-cargo@sha256:" + "a" * 64
    case("runtime.publication-validation", "publication-wrong-image",
         lambda: publication.validate_publication_evidence(
             Path("unused-public-fixture"), {}, image="ghcr.io/unapproved/image@sha256:" + "a" * 64,
             publisher_revision="b" * 40,
         ))
    case("runtime.publication-validation", "publication-wrong-revision",
         lambda: publication.validate_publication_evidence(
             Path("unused-public-fixture"), {}, image=public_image,
             publisher_revision="not-a-commit",
         ))

    def binding_case(valid):
        def invoke(function):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "package-after.json"
                path.write_bytes(json.dumps({
                    "name": "feature-regression-rust-cargo-restricted", "owner": "ElevenID",
                    "package_type": "container", "visibility": "private" if valid else "public",
                }, sort_keys=True, separators=(",", ":")).encode())
                return function(
                    {"schema": "elevenid.rust-cargo-publication/v2",
                     "distribution": "restricted", "private_evidence_bound": False,
                     "image": "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "a" * 64},
                    "ghcr.io/elevenid/feature-regression-rust-cargo-restricted@sha256:" + "b" * 64,
                    path,
                )
        return available_function(publication, "bind_private_evidence", invoke)

    case("runtime.private-publication", "private-evidence-bound", binding_case(True))
    case("runtime.private-publication", "private-evidence-public-package", binding_case(False))

    return cases


def observe():
    observations = []
    for operation, name, function in probe_cases():
        try:
            result = function()
            # A policy findings list is itself the production diagnostic and
            # rejection decision, not a successful admission merely because the
            # Python function returned normally.
            rejected = operation in {"policy.source-reader", "policy.restricted-publisher"} and bool(result)
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
