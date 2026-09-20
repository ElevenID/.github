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
    assert capture["schema"] == "elevenid.behavior-subject-capture/v2"
    by_dimension = {
        item["dimension"]: item["value"] for item in capture["observations"]
    }
    assert set(by_dimension) == {
        "public_status",
        "public_message",
        "safe_server_diagnostic",
    }
    assert isinstance(by_dimension["public_status"], str)
    assert by_dimension["public_status"].startswith("HTTP ")
    assert isinstance(by_dimension["public_message"], str)
    assert by_dimension["public_message"].strip()
    diagnostic = by_dimension["safe_server_diagnostic"]
    assert isinstance(diagnostic, dict)
    assert diagnostic.get("category") and diagnostic.get("stage")
    raise SystemExit(0)
observations = [
    {
        **observed,
        "id": f"{observed['case_id']}.{observed['dimension']}.{args.phase}",
        "producer_test": (
            f"test:{args.repository}@{args.revision}:tests/test_api.py::"
            "test_approval_provider_failure"
        ),
    }
    for observed in capture["observations"]
]
document = {
    "schema": "elevenid.behavior-observations-runtime/v2",
    "repository": args.repository,
    "revision": args.revision,
    "phase": args.phase,
    "observations": observations,
}
sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
