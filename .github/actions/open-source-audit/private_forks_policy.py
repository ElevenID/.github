"""Validate the reviewed source-reader boundary, without executing repository code.

This is a limited policy for owner-authored internal workflows. The separately
reviewed helper enforces event trust and Git credential scope at runtime; its
digest is part of this policy, not a repository-controlled exemption.
"""
from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path

import yaml


TOKEN = "PRIVATE_FORKS_READ_TOKEN"
FLAG = "vars.PRIVATE_FORKS_ENABLED == 'true'"
NATIVE = FLAG + " && (matrix.role == 'services' || matrix.role == 'migrations')"
DIRECT = "${{ secrets." + TOKEN + " }}"
CONDITIONAL = "${{ " + FLAG + " && secrets." + TOKEN + " || '' }}"
NATIVE_TOKEN = "${{ " + NATIVE + " && secrets." + TOKEN + " || '' }}"
FLAG_VALUE = "${{ " + FLAG + " && 'true' || 'false' }}"
RECORD_VALUE = "${{ vars.PRIVATE_FORKS_ENABLED != 'true' && 'true' || 'false' }}"
HELPER = ".github/scripts/private-forks.py"
HELPER_SHA256 = "dab5eb206c9548f3a1074f604b9e516058ed4094415cb05df0036eda935f8fc4"
REPOSITORIES = {"ElevenID/marty-" + name for name in ("core", "ui", "verifier", "credentials")}
EVENTS = {"pull_request", "merge_group", "push", "workflow_dispatch", "schedule", "repository_dispatch"}
CONDITIONS = {
    FLAG, NATIVE,
    FLAG + " && needs.changes.outputs.rollback_test_only != 'true' && needs.changes.outputs.didcomm_release_test_only != 'true'",
    FLAG + " && steps.update.outputs.changed == 'true'",
    FLAG + " && steps.core-wheel-cache.outputs.cache-hit != 'true'",
}
HELPER_PATHS = {
    "ElevenID/marty-core": {HELPER},
    "ElevenID/marty-ui": {HELPER, "marty-ui/" + HELPER, "$RUNNER_TEMP/marty-private-forks.py"},
    "ElevenID/marty-verifier": {"$GITHUB_WORKSPACE/" + HELPER, "$GITHUB_WORKSPACE/private-forks-ci/" + HELPER},
    "ElevenID/marty-credentials": {"$GITHUB_WORKSPACE/" + HELPER, "$GITHUB_WORKSPACE/marty-credentials/" + HELPER},
}
CORE_PACKAGES = {"marty-crypto", "marty-verification", "marty-biometrics", "marty-secure-storage", "marty-types", "marty-oid4vci"}
BUILD_ACTION = "docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc"
PRODUCT_ACTION = "./.github/actions/build-product-image"
# These are the reviewed secret-mount implementations, not whole workflows.
DOCKER_FILES = {
    "services/Dockerfile": "39a407063f7cbf89eb23c4d7121db3df69cfa826be1e2fb0e125733711e74362",
    "services/Dockerfile.migrations": "66cd05d2153f018cf1637a5f4a73864ff73ea01550ea06cc10d670a7df7bbb3d",
    "rust/services/Dockerfile.ci": "15a6b1386bbe916c0a353067ec72dd814012c8d6b26dca93e82a39c4e5c85974",
    "scripts/ci/run-public-rust-build.sh": "092240cb773a65fb97ee5d8454ee2bf47fa1cf2fa0ea045b9a1c0adf06652f8c",
    "services/Dockerfile.dockerignore": "cb704677050baa10021003ece3ce4d70381ed3321e654341397150d3237899e6",
    "services/Dockerfile.migrations.dockerignore": "a104071b34eb62679bc002542d78373e74ee18f75a81307a94e87c6598ee42ea",
    "rust/services/Dockerfile.ci.dockerignore": "02f8efd45cb13431c6f60402f6298111f93f737c72800a1d7e08748a7d7921dd",
}
PRODUCT_FILES = {
    ".github/actions/build-product-image/action.yml": "564ae35eb529c2d8a3da784b6d86d1bbca99e28469c141c633f84b0c092993c0",
    "scripts/product_image_build.py": "0342f2367082e4b07dbb9e4d6eaa2ec435cebe60a23b6d635009aa960a57b63e",
}
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SECRET_CONTEXT = re.compile(r"\bsecrets\b", re.I)
STATUS_FUNCTION = re.compile(r"\b(?:always|failure|cancelled|success)\s*\(", re.I)
PROTECTED_ENV = {"GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR", "GITHUB_WORKSPACE", "RUNNER_TEMP"}


class WorkflowLoader(yaml.BaseLoader):
    """Keep Actions' `on` key a string and reject ambiguous duplicate mappings."""


def unique_mapping(loader: WorkflowLoader, node: yaml.MappingNode) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("workflow contains a duplicate or non-string mapping key")
        result[key] = loader.construct_object(value_node)
    return result


WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def secret_values(value: object, prefix: tuple = ()) -> list[tuple[tuple, str]]:
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in secret_values(child, prefix + (key,))]
    if isinstance(value, list):
        return [item for index, child in enumerate(value) for item in secret_values(child, prefix + (index,))]
    if isinstance(value, str) and any(SECRET_CONTEXT.search(part) for part in EXPRESSION.findall(value)):
        return [(prefix, value)]
    return []


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def reviewed_file(root: Path, relative: str, digest: str) -> None:
    path = root / relative
    require(path.is_file() and not path.is_symlink(), f"reviewed file missing: {relative}")
    require(path.resolve().is_relative_to(root.resolve()), "reviewed file escapes repository")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, f"reviewed file changed: {relative}")


def normal_step(step: dict) -> None:
    require(step.get("continue-on-error", "false") in (False, "false"), "reader/trust step ignores failure")
    require(not STATUS_FUNCTION.search(str(step.get("if", ""))), "reader/trust step overrides normal success ordering")
    require(not (PROTECTED_ENV & set(step.get("env", {}))), "reader/trust step overrides trusted runner context")


def helper_path(value: str) -> str:
    return value.replace("${RUNNER_TEMP}", "$RUNNER_TEMP")


def check_program(step: dict, repository: str) -> str:
    normal_step(step)
    require(not step.get("env") and not secret_values(step), "trust check receives credentials or custom environment")
    require(step.get("shell") == "bash", "trust check must use fail-fast bash")
    require(step.get("working-directory") == "${{ github.workspace }}", "trust check must run from the workspace")
    require(step.get("if") in CONDITIONS, "trust check has an unreviewed condition")
    lines = str(step.get("run", "")).strip().splitlines()
    if repository == "ElevenID/marty-core" and len(lines) == 2:
        require(lines.pop() == "printf '%s\\n' 'RUSTC_WRAPPER=' 'SCCACHE_GHA_ENABLED=false' >> \"$GITHUB_ENV\"", "unreviewed trust-check tail")
    if repository == "ElevenID/marty-ui" and len(lines) == 2:
        require(lines.pop(0) == 'cp ".github/scripts/private-forks.py" "$RUNNER_TEMP/marty-private-forks.py"', "unreviewed helper copy")
    require(len(lines) == 1, "trust check must only run the reviewed checker")
    command = shlex.split(lines[0])
    require(len(command) == 3 and command[0] in {"python", "python3"} and command[2] == "check", "invalid trust-check command")
    path = helper_path(command[1])
    require(path in HELPER_PATHS[repository], "trust check uses an unreviewed helper path")
    return path


def host_fetch(step: dict, repository: str) -> tuple[str, str]:
    require(step.get("env") == {TOKEN: DIRECT}, "host reader must be the sole fetch-step environment value")
    require(step.get("shell") == "bash" and not step.get("uses"), "host reader is only allowed in the fetch command")
    require(step.get("if") in CONDITIONS, "fetch has an unreviewed activation condition")
    require(step.get("working-directory", "${{ github.workspace }}") == "${{ github.workspace }}", "fetch must run from the workspace")
    command = shlex.split(str(step.get("run", "")))
    require(len(command) >= 3 and command[0] in {"python", "python3"}, "reader is not used by the reviewed fetch helper")
    path = helper_path(command[1])
    require(path in HELPER_PATHS[repository], "fetch uses an unreviewed helper path")
    require(command[2] in {"fetch", "update-core"}, "reader may not be used by compilation, tests, or arbitrary commands")
    args = command[3:]
    require(len(args) % 2 == 0, "invalid fetch arguments")
    packages = []
    for option, value in zip(args[::2], args[1::2]):
        if option == "--manifest-path":
            require(re.fullmatch(r"(?:\$GITHUB_WORKSPACE/)?(?:[A-Za-z0-9_.-]+/)*Cargo\.toml", value) is not None and ".." not in value.split("/"), "manifest must be a fixed workspace Cargo.toml")
        elif option == "--package" and command[2] == "update-core":
            packages.append(value)
        else:
            raise ValueError("unreviewed fetch argument")
    if command[2] == "update-core":
        require(repository == "ElevenID/marty-verifier" and len(packages) == 6 and set(packages) == CORE_PACKAGES, "update-core must retain the reviewed six public packages")
    return path, step["if"]


def docker_fetch(root: Path, step: dict, job: dict, repository: str) -> tuple[str, str]:
    require(repository == "ElevenID/marty-ui", "BuildKit reader is only reviewed for the UI consumer")
    require(not step.get("run") and step.get("uses") in {BUILD_ACTION, PRODUCT_ACTION}, "unreviewed reader action")
    for path, digest in DOCKER_FILES.items():
        reviewed_file(root, path, digest)
    values = step.get("with", {})
    if step["uses"] == PRODUCT_ACTION:
        require(not step.get("env"), "product reader may only use the dedicated action input")
        require(values.get("private-forks-read-token") == NATIVE_TOKEN, "product token must be limited to enabled native rows")
        require(values.get("private-forks-enabled") == "${{ " + NATIVE + " && 'true' || 'false' }}", "product reader activation differs")
        for path, digest in PRODUCT_FILES.items():
            reviewed_file(root, path, digest)
        return HELPER, NATIVE
    env = step.get("env", {})
    require(env.get(TOKEN) == CONDITIONAL and set(env) <= {TOKEN, "DOCKER_BUILD_RECORD_UPLOAD"}, "BuildKit reader must be scoped to its action environment")
    record = env.get("DOCKER_BUILD_RECORD_UPLOAD", job.get("env", {}).get("DOCKER_BUILD_RECORD_UPLOAD"))
    require(record in ("false", RECORD_VALUE), "private BuildKit records must not be exported")
    require(values.get("context") == "." and values.get("file") in DOCKER_FILES, "unreviewed Docker context or recipe")
    file = values["file"]
    require(file.endswith(("Dockerfile", "Dockerfile.migrations", "Dockerfile.ci")), "not a reviewed Dockerfile")
    target = values.get("target", "")
    runtime_targets = set(re.findall(r"^FROM runtime AS ([a-z_]+)$", (root / file).read_text(), re.M))
    require(target == "" or target in runtime_targets, "reader build may not export an intermediate source stage")
    require(not any(values.get(key) for key in ("secrets", "secret-files", "ssh", "build-contexts")), "unreviewed Docker credential/context inputs")
    bindings = set(str(values.get("secret-envs", "")).splitlines())
    require("private_forks_read_token=" + TOKEN in bindings, "missing dedicated fetch secret")
    require(bindings <= {"private_forks_read_token=" + TOKEN, "sccache_token=SCCACHE_GHA_RUNTIME_TOKEN", "sccache_url=SCCACHE_GHA_CACHE_URL", "sccache_mode=SCCACHE_GHA_RW_MODE"}, "unreviewed BuildKit secret bindings")
    args = str(values.get("build-args", "")).splitlines()
    require(args.count("PRIVATE_FORKS_ENABLED=" + FLAG_VALUE) == 1, "Docker private mode must match reader activation")
    require(not any(TOKEN in line or "secrets." in line for line in args), "reader may not be a Docker build argument")
    for key in ("cache-from", "cache-to"):
        value = values.get(key, "")
        require(value == "" or re.fullmatch(r"\$\{\{ vars\.PRIVATE_FORKS_ENABLED != 'true' && 'type=gha,[^'\n]+' \|\| '' \}\}", value) is not None, "private Docker cache export/import is prohibited")
    return HELPER, FLAG


def workflow_secret_findings(root: Path, content: str, repository: str) -> list[str]:
    """Return structural policy findings, never execute helpers from the tree."""
    try:
        document = yaml.load(content, Loader=WorkflowLoader)
        require(isinstance(document, dict), "workflow must be a mapping")
        events = document.get("on", {})
        events = {events} if isinstance(events, str) else set(events or [])
        references = secret_values(document)
        fork_workflow = "pull_request" in events
        readers = [(path, value) for path, value in references if TOKEN in value]
        jobs = document.get("jobs", {})
        for scope in (document, *jobs.values()):
            require(TOKEN not in scope.get("env", {}), "source reader must not be a workflow/job environment variable")
        for job in jobs.values():
            for step in job.get("steps", []):
                declares_reader = TOKEN in step.get("env", {}) or "private-forks-read-token" in step.get("with", {})
                require(not declares_reader or any(TOKEN in value for _, value in secret_values(step)), "unreviewed reader binding")
        findings = []
        if "pull_request_target" in events:
            findings.append("pull_request_target is prohibited")
        if not readers:
            return findings + (["fork workflow references repository secrets"] if fork_workflow and references else [])
        require(repository in REPOSITORIES, "source reader is not approved for this repository")
        require(events <= EVENTS, "source reader has an unsupported workflow event")
        reviewed_file(root, HELPER, HELPER_SHA256)
        consumed = set()
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for scope in (document, job):
                env = scope.get("env", {})
                require(not (PROTECTED_ENV & set(env)), "workflow/job overrides trusted runner context")
            for index, step in enumerate(steps):
                refs = secret_values(step)
                if not any(TOKEN in value for _, value in refs):
                    continue
                normal_step(step)
                require(len(refs) == 1, "reader step must not receive other repository secrets")
                require(refs[0][0] in {("env", TOKEN), ("with", "private-forks-read-token")}, "reader must use its dedicated step input")
                if step.get("uses"):
                    path, activation = docker_fetch(root, step, job, repository)
                else:
                    defaults = {**document.get("defaults", {}).get("run", {}), **job.get("defaults", {}).get("run", {})}
                    require(step.get("working-directory", defaults.get("working-directory", "${{ github.workspace }}")) == "${{ github.workspace }}", "fetch inherits an unreviewed working directory")
                    path, activation = host_fetch(step, repository)
                checked = False
                for previous in steps[:index]:
                    if "private-forks.py" not in str(previous.get("run", "")) or " check" not in str(previous.get("run", "")):
                        continue
                    checker = check_program(previous, repository)
                    condition = previous["if"]
                    if checker == path and (activation == condition or activation.startswith(condition + " &&")):
                        checked = True
                require(checked, "reader lacks a prior credential-free trust check that always covers its activation")
                consumed.add(("jobs", job_name, "steps", index) + refs[0][0])
        for path, value in references:
            if path not in consumed and (fork_workflow or TOKEN in value):
                findings.append("repository secret is outside the reviewed source-fetch step")
        return findings
    except (ValueError, TypeError, AttributeError, OSError, yaml.YAMLError) as error:
        return [str(error)]
