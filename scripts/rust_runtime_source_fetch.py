"""Main-only, reviewed-bundle source fetch; never run candidate build scripts."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import sys
import tempfile

if __package__:
    from .rust_runtime_bundle import load_bundle, verify_target
    from .rust_runtime_source_access import locked_git_sources
    from .feature_regression_observation_runner import _run_process
else:
    from rust_runtime_bundle import load_bundle, verify_target
    from rust_runtime_source_access import locked_git_sources
    from feature_regression_observation_runner import _run_process


TOKEN = "PRIVATE_FORKS_READ_TOKEN"
PRIVATE_FORKS = {
    "elevenid/ssi-elevenid",
    "elevenid/isomdl-elevenid",
    "elevenid/sd-jwt-rust",
}
CALLER_REPOSITORY = "ElevenID/feature-regression-private-publisher"
CALLER_WORKFLOW_REF = (
    CALLER_REPOSITORY + "/.github/workflows/publish-restricted-rust-probe-runtime.yml@refs/heads/main"
)
WORKFLOW_REPOSITORY = "ElevenID/.github"
WORKFLOW_REF = WORKFLOW_REPOSITORY + "/.github/workflows/publish-restricted-rust-probe-runtime.yml@refs/heads/main"
TARGET = ".rust-runtime-target"
CACHE = ".rust-runtime-cargo-cache"


class FetchError(ValueError):
    pass


def require_context(environment: dict[str, str], event: dict) -> None:
    if (
        environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("GITHUB_REPOSITORY") != CALLER_REPOSITORY
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_WORKFLOW_REF") != CALLER_WORKFLOW_REF
        or environment.get("PUBLISHER_WORKFLOW_REPOSITORY") != WORKFLOW_REPOSITORY
        or environment.get("PUBLISHER_WORKFLOW_REF") != WORKFLOW_REF
        or not re.fullmatch(r"[0-9a-f]{40}", environment.get("PUBLISHER_WORKFLOW_SHA", ""))
        or not re.fullmatch(r"[0-9a-f]{40}", environment.get("GITHUB_SHA", ""))
        or not environment.get("GITHUB_ACTOR")
        or "dependabot[bot]"
        in {
            environment.get("GITHUB_ACTOR", "").casefold(),
            environment.get("GITHUB_TRIGGERING_ACTOR", "").casefold(),
        }
        or not isinstance(event.get("repository"), dict)
        or event["repository"].get("full_name") != CALLER_REPOSITORY
    ):
        raise FetchError(
            "restricted runtime source fetch requires protected main publisher dispatch"
        )


def credential_response(
    operation: str, request: str, environment: dict[str, str]
) -> str:
    if operation != "get":
        return ""
    fields = {}
    for line in request.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            if name in fields:
                return ""
            fields[name] = value
    if (
        fields.get("protocol") != "https"
        or fields.get("host", "").casefold() != "github.com"
        or fields.get("path", "").casefold().removesuffix(".git") not in PRIVATE_FORKS
    ):
        return ""
    token = environment.get(TOKEN, "")
    if re.fullmatch(r"[A-Za-z0-9_.\-]{8,512}", token) is None:
        raise FetchError("restricted runtime source credential is missing or invalid")
    return "username=x-access-token\npassword=" + token + "\n\n"


def fetch_environment(cache: pathlib.Path) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(
            (
                "CARGO_",
                "GIT_CONFIG_",
                "GIT_TRACE",
                "RUSTFLAGS",
                "RUSTC",
                "RUSTDOC",
                "LD_",
                "DYLD_",
            )
        )
    }
    environment.update(
        CARGO_HOME=str(cache),
        CARGO_NET_OFFLINE="false",
        CARGO_NET_GIT_FETCH_WITH_CLI="true",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
        SSH_ASKPASS="",
        RUSTUP_TOOLCHAIN="1.95.0",
    )
    helper = (
        "!"
        + shlex.quote(pathlib.Path(sys.executable).as_posix())
        + " "
        + shlex.quote(pathlib.Path(__file__).resolve().as_posix())
        + " credential"
    )
    settings = [
        ("credential.helper", ""),
        ("credential.helper", helper),
        ("credential.useHttpPath", "true"),
        ("credential.interactive", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("http.followRedirects", "false"),
    ]
    environment["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (name, value) in enumerate(settings):
        environment[f"GIT_CONFIG_KEY_{index}"] = name
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def checked_bundle(root: pathlib.Path, bundle_id: str) -> dict[str, str]:
    root = root.resolve()
    with pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
        raw = stream.read(2_097_153)
    if len(raw) > 2_097_152:
        raise FetchError("publisher event exceeds its bound")
    event = json.loads(raw.decode("utf-8"))
    if not isinstance(event, dict):
        raise FetchError("publisher event must be an object")
    require_context(os.environ.copy(), event)
    git = shutil.which("git")
    if git is None:
        raise FetchError("Git is required for publisher source verification")
    environment = os.environ.copy()
    environment.pop(TOKEN, None)

    def command(args):
        return (
            _run_process(
                [
                    git,
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    *args,
                ],
                environment,
                label="publisher source verification",
                timeout=30,
                stdout_limit=65_536,
                stderr_limit=65_536,
            )[0]
            .decode()
            .strip()
        )

    if command(["-C", str(root), "rev-parse", "HEAD"]) != os.environ["PUBLISHER_WORKFLOW_SHA"]:
        raise FetchError("publisher checkout differs from protected workflow revision")
    bundle = load_bundle(root / "runtime/rust-cargo/bundles.json", bundle_id)
    target = root / TARGET
    if not target.is_dir() or target.is_symlink():
        raise FetchError("publisher target must be an ordinary checkout")
    if command(["-C", str(target), "rev-parse", "HEAD"]) != bundle["revision"]:
        raise FetchError("publisher target differs from the reviewed bundle revision")
    if command(
        [
            "-C",
            str(target),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored",
        ]
    ):
        raise FetchError("publisher target must be pristine including ignored inputs")
    for directory, directories, files in os.walk(target, followlinks=False):
        if pathlib.Path(directory) == target:
            directories[:] = [name for name in directories if name != ".git"]
        for name in [*directories, *files]:
            path = pathlib.Path(directory) / name
            if path.is_symlink() or name == ".cargo" or name == ".git":
                raise FetchError(
                    "publisher target contains unsupported links or Cargo configuration"
                )
    verify_target(target, bundle)
    locked_git_sources((target / bundle["lock_path"]).read_bytes())
    return bundle


def fetch(root: pathlib.Path, bundle_id: str) -> None:
    root = root.resolve()
    bundle = checked_bundle(root, bundle_id)
    if re.fullmatch(r"[A-Za-z0-9_.\-]{8,512}", os.environ.get(TOKEN, "")) is None:
        raise FetchError("restricted runtime source credential is missing or invalid")
    cache = root.resolve() / CACHE
    if cache.exists() or cache.is_symlink():
        raise FetchError("restricted runtime source cache must be fresh")
    cache.mkdir(mode=0o700)
    environment = fetch_environment(cache)
    cargo = shutil.which("cargo")
    if cargo is None:
        raise FetchError("pinned Cargo toolchain is unavailable")
    previous = pathlib.Path.cwd()
    try:
        # Cargo's config discovery starts in a trusted, fresh directory outside
        # the target. The token is never used for compilation or image building.
        with tempfile.TemporaryDirectory(prefix="elevenid-runtime-fetch-") as directory:
            try:
                os.chdir(directory)
                _run_process(
                    [
                        cargo,
                        "fetch",
                        "--locked",
                        "--manifest-path",
                        str(root / TARGET / bundle["manifest_path"]),
                    ],
                    environment,
                    label="restricted runtime dependency fetch",
                    timeout=900,
                    stdout_limit=65_536,
                    stderr_limit=2_097_152,
                )
            finally:
                # Leave before TemporaryDirectory removes its directory on Windows.
                os.chdir(previous)
    finally:
        os.chdir(previous)
        environment.pop(TOKEN, None)
        os.environ.pop(TOKEN, None)
    if any(
        (cache / name).exists()
        for name in ("credentials", "credentials.toml", "config", "config.toml")
    ):
        raise FetchError("source fetch unexpectedly persisted Cargo credentials")
    checked_bundle(root, bundle_id)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "fetch", "credential", "cleanup"))
    parser.add_argument("operation", nargs="?")
    parser.add_argument("--bundle-id")
    args = parser.parse_args(argv)
    try:
        if args.command == "credential":
            request = sys.stdin.read(8193)
            if len(request) > 8192:
                raise FetchError("credential request exceeds its bound")
            sys.stdout.write(
                credential_response(args.operation, request, os.environ.copy())
            )
        elif args.command == "cleanup":
            cache = pathlib.Path.cwd() / CACHE
            if cache.is_symlink():
                raise FetchError("publisher cache cleanup refuses a link")
            if cache.exists():
                if not cache.is_dir() or not cache.resolve().is_relative_to(
                    pathlib.Path.cwd().resolve()
                ):
                    raise FetchError(
                        "publisher cache cleanup refuses an unexpected path"
                    )
                shutil.rmtree(cache)
        elif args.command == "check":
            if os.environ.get(TOKEN):
                raise FetchError("publisher trust check must be credential-free")
            checked_bundle(pathlib.Path.cwd(), args.bundle_id)
        else:
            fetch(pathlib.Path.cwd(), args.bundle_id)
        return 0
    except Exception:
        # Cargo/Git diagnostics can contain private source or credential errors.
        # No raw exception, process output, or source line is public evidence.
        print(
            "ERROR: restricted runtime source boundary refused the operation",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
