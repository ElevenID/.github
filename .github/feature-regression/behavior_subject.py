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
            rust_build=None,
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
            rejected = operation.startswith("policy.") and bool(result)
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
