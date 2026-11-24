"""Host-only access to the fixed private regression-runtime package."""

from __future__ import annotations

import contextlib
import argparse
import json
import os
import pathlib
import re
import tempfile
import sys
import urllib.error
import urllib.request
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from typing import Any


PACKAGE = "feature-regression-rust-cargo-restricted"
PACKAGE_URL = "https://api.github.com/orgs/ElevenID/packages/container/" + PACKAGE
IMAGE = re.compile(r"ghcr\.io/elevenid/" + PACKAGE + r"@sha256:[0-9a-f]{64}")


class RegistryAccessError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require_private_package(token: str) -> dict[str, str]:
    """Publisher/admin metadata check; the REST endpoint requires a classic PAT.

    A workflow job token is used only for the consumer's registry pull below.
    Do not silently substitute it for this independently qualified admin proof.
    """
    if re.fullmatch(r"[A-Za-z0-9_.\-]{8,512}", token) is None:
        raise RegistryAccessError(
            "restricted runtime package credential is missing or invalid"
        )
    request = urllib.request.Request(
        PACKAGE_URL,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ElevenID-restricted-runtime",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=30
        ) as response:
            raw = response.read(1_048_577)
            if response.status != 200 or len(raw) > 1_048_576:
                raise RegistryAccessError(
                    "restricted runtime package metadata is unavailable"
                )
        document = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        urllib.error.HTTPError,
        ValueError,
    ) as error:
        raise RegistryAccessError(
            "restricted runtime package metadata is unavailable"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("name") != PACKAGE
        or document.get("package_type") != "container"
        or document.get("visibility") != "private"
        or not isinstance(document.get("owner"), dict)
        or str(document["owner"].get("login", "")).casefold() != "elevenid"
    ):
        raise RegistryAccessError(
            "restricted runtime package must already exist and be private"
        )
    return {
        "name": PACKAGE,
        "owner": "ElevenID",
        "package_type": "container",
        "visibility": "private",
    }


def require_anonymous_pull_denied() -> None:
    query = urllib.parse.urlencode(
        {"service": "ghcr.io", "scope": "repository:elevenid/" + PACKAGE + ":pull"}
    )
    request = urllib.request.Request(
        "https://ghcr.io/token?" + query,
        headers={"User-Agent": "ElevenID-restricted-runtime"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=30
        ) as response:
            # An anonymous registry token must never authorize this repository.
            response.read(1)
    except urllib.error.HTTPError as error:
        try:
            raw = error.read(65_537)
            value = json.loads(raw.decode("utf-8")) if len(raw) <= 65_536 else None
            errors = value.get("errors") if isinstance(value, dict) else None
            if (
                error.code in {401, 403}
                and isinstance(errors, list)
                and errors
                and all(
                    isinstance(item, dict)
                    and item.get("code") in {"DENIED", "UNAUTHORIZED"}
                    for item in errors
                )
            ):
                return
        except (ValueError, UnicodeDecodeError, OSError):
            pass
        finally:
            error.close()
        raise RegistryAccessError(
            "anonymous registry refusal was not established"
        ) from None
    except OSError as error:
        raise RegistryAccessError(
            "anonymous registry refusal was not established"
        ) from error
    raise RegistryAccessError(
        "restricted runtime repository permits anonymous registry access"
    )


def require_execution_context(
    *,
    repository: str,
    revision: str,
    event_name: str,
    environment: Mapping[str, str],
) -> None:
    actor = environment.get("GITHUB_ACTOR", "")
    triggering = environment.get("GITHUB_TRIGGERING_ACTOR", actor)
    if (
        environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("GITHUB_REPOSITORY", "").casefold() != repository.casefold()
        or not repository.startswith("ElevenID/")
        or environment.get("GITHUB_EVENT_NAME") != event_name
        or not actor
        or not triggering
        or "dependabot[bot]" in {actor.casefold(), triggering.casefold()}
    ):
        raise RegistryAccessError(
            "restricted runtime execution context is not authorized"
        )
    try:
        event_path = pathlib.Path(environment["GITHUB_EVENT_PATH"])
        with event_path.open("rb") as stream:
            raw = stream.read(2_097_153)
        if len(raw) > 2_097_152:
            raise RegistryAccessError("restricted runtime event exceeds its bound")
        event = json.loads(raw.decode("utf-8"))
    except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryAccessError("restricted runtime event is unavailable") from error
    if (
        not isinstance(event, dict)
        or not isinstance(event.get("repository"), dict)
        or str(event["repository"].get("full_name", "")).casefold()
        != repository.casefold()
    ):
        raise RegistryAccessError("restricted runtime event repository differs")
    if event_name == "pull_request":
        pr = event.get("pull_request", {})
        if not isinstance(pr, dict):
            raise RegistryAccessError("restricted runtime pull request is malformed")
        head, base, author = pr.get("head", {}), pr.get("base", {}), pr.get("user", {})
        number = event.get("number")
        if (
            not all(isinstance(value, dict) for value in (head, base, author))
            or not isinstance(number, int)
            or isinstance(number, bool)
            or number <= 0
            or environment.get("GITHUB_REF") != f"refs/pull/{number}/merge"
            or not author.get("login")
            or author.get("type") != "User"
            or str(author.get("login", "")).casefold() == "dependabot[bot]"
            or head.get("sha") != revision
            or any(
                not isinstance(side.get("repo"), dict)
                or str(side["repo"].get("full_name", "")).casefold()
                != repository.casefold()
                for side in (head, base)
            )
        ):
            raise RegistryAccessError(
                "restricted runtime requires an internal exact-head human pull request"
            )
    elif (
        event_name not in {"push", "schedule", "workflow_dispatch"}
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_SHA") != revision
    ):
        raise RegistryAccessError("restricted runtime baseline must bind current main")


@contextlib.contextmanager
def private_pull_environment(
    *,
    docker: str,
    image: str,
    token: str,
    actor: str,
    run_process: Callable[..., Any],
) -> Iterator[dict[str, str]]:
    if (
        IMAGE.fullmatch(image) is None
        or re.fullmatch(r"[A-Za-z0-9_\-\[\]]{1,100}", actor) is None
        or re.fullmatch(r"[A-Za-z0-9_.\-]{8,512}", token) is None
    ):
        raise RegistryAccessError("restricted runtime pull identity is invalid")
    require_anonymous_pull_denied()
    with tempfile.TemporaryDirectory(prefix="elevenid-runtime-registry-") as temporary:
        # This directory is never included in the /workspace mount or build
        # context. No registry credential is passed through container --env.
        workspace = os.environ.get("GITHUB_WORKSPACE")
        if workspace and pathlib.Path(temporary).resolve().is_relative_to(
            pathlib.Path(workspace).resolve()
        ):
            raise RegistryAccessError(
                "registry credentials cannot be stored in the target checkout"
            )
        environment = os.environ.copy()
        for name in (
            "RUST_RUNTIME_PULL_TOKEN",
            "PRIVATE_FORKS_READ_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ):
            environment.pop(name, None)
        environment["DOCKER_CONFIG"] = temporary
        try:
            run_process(
                [docker, "login", "ghcr.io", "--username", actor, "--password-stdin"],
                environment,
                label="restricted runtime registry login",
                timeout=30,
                stdout_limit=65_536,
                stderr_limit=65_536,
                stdin_data=token.encode("utf-8"),
            )
            yield environment
            # A denial alone does not prove existence. Authenticated pull and
            # exact RepoDigest verification must succeed between both probes.
            require_anonymous_pull_denied()
        finally:
            run_process(
                [docker, "logout", "ghcr.io"],
                environment,
                label="restricted runtime registry logout",
                timeout=30,
                stdout_limit=65_536,
                stderr_limit=65_536,
            )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check-private-package",))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    token = os.environ.pop("RUST_RUNTIME_PACKAGE_METADATA_TOKEN", "")
    try:
        metadata = require_private_package(token)
        token = ""
        with args.output.open("xb") as stream:
            stream.write(
                json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
            )
        return 0
    except (RegistryAccessError, OSError):
        print(
            "ERROR: restricted runtime package must be precreated, private, and readable by the metadata credential",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
