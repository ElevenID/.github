"""Validate and phase-bind the runner's real source-free subject capture."""

from __future__ import annotations

import argparse
import json
import re
import sys


DIMENSIONS = {"public_status", "public_message", "safe_server_diagnostic"}
IDENTIFIER = re.compile(r"[a-z][a-z0-9.-]{0,99}")
REVISION = re.compile(r"[0-9a-f]{40}")
MAX_CAPTURE_BYTES = 1_048_576
TEST_PATH = "tests/test_policy_enrollment_subject.py"
TEST_NAME = "test_real_policy_runner_and_bundle_boundaries"


def unique_pairs(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("capture contains duplicate JSON fields")
        document[key] = value
    return document


def sanitized(value):
    if isinstance(value, dict):
        for key, child in value.items():
            sanitized(key)
            sanitized(child)
    elif isinstance(value, list):
        for child in value:
            sanitized(child)
    elif isinstance(value, str) and any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("capture contains a control character")


def test_capture(capture):
    """Enforce the actual subject triple and its measured result relationships."""
    if not isinstance(capture, dict) or set(capture) != {"schema", "receipt", "observations"}:
        raise ValueError("capture fields are invalid")
    if capture["schema"] != "elevenid.behavior-subject-capture/v2" or not isinstance(capture["receipt"], dict):
        raise ValueError("capture schema or runner receipt is invalid")
    observations = capture["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("capture observations are missing")
    cases = {}
    identities = set()
    for observation in observations:
        if not isinstance(observation, dict) or set(observation) != {
            "id", "operation_id", "case_id", "dimension", "value",
        }:
            raise ValueError("capture observation fields are invalid")
        operation = observation["operation_id"]
        name = observation["case_id"]
        dimension = observation["dimension"]
        if (not isinstance(operation, str) or IDENTIFIER.fullmatch(operation) is None
                or not isinstance(name, str) or IDENTIFIER.fullmatch(name) is None
                or dimension not in DIMENSIONS
                or observation["id"] != f"{name}.{dimension}"
                or (name, dimension) in identities):
            raise ValueError("capture observation identity is invalid")
        identities.add((name, dimension))
        if name in cases and cases[name][0] != operation:
            raise ValueError("capture case changed its operation")
        cases.setdefault(name, (operation, {}))[1][dimension] = observation["value"]
    for _, values in cases.values():
        if set(values) != DIMENSIONS:
            raise ValueError("capture case does not contain its exact triple")
        status = values["public_status"]
        message = values["public_message"]
        diagnostic = values["safe_server_diagnostic"]
        if not isinstance(diagnostic, dict):
            raise ValueError("capture diagnostic must be an object")
        if status == "accepted":
            if message is not None or set(diagnostic) != {"returned"}:
                raise ValueError("accepted capture result is inconsistent")
        elif status == "not_present":
            if message is not None or diagnostic != {"availability": "absent"}:
                raise ValueError("absent production owner result is inconsistent")
        elif status == "rejected":
            if isinstance(message, str):
                if not message or set(diagnostic) != {"exception"}:
                    raise ValueError("exception result is inconsistent")
            elif isinstance(message, list):
                if not message or set(diagnostic) != {"returned"} or diagnostic["returned"] != message:
                    raise ValueError("policy rejection result is inconsistent")
            else:
                raise ValueError("rejection message is invalid")
        else:
            raise ValueError("capture status is invalid")
    sanitized(capture)
    return observations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("test", "emit"))
    parser.add_argument("--repository")
    parser.add_argument("--revision")
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_CAPTURE_BYTES + 1)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds its bound")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    observations = test_capture(capture)
    if args.command == "test":
        return
    if args.repository != "ElevenID/.github" or not isinstance(args.revision, str) or REVISION.fullmatch(args.revision) is None:
        raise ValueError("observation target identity is invalid")
    reference = f"test:{args.repository}@{args.revision}:{TEST_PATH}::{TEST_NAME}"
    output = {
        "schema": "elevenid.behavior-observations-runtime/v2",
        "repository": args.repository,
        "revision": args.revision,
        "phase": args.phase,
        "observations": [
            {**item, "id": f"{item['case_id']}.{item['dimension']}.{args.phase}",
             "producer_test": reference}
            for item in observations
        ],
    }
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
