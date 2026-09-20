import json
import sys

from src.api import probe_behavior

observed = probe_behavior()
document = {
    "schema": "elevenid.behavior-subject-output/v1",
    "observations": [
        {
            "id": "approval-provider-failure.public_status.after",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "public_status",
            "value": observed["public_status"],
        },
        {
            "id": "approval-provider-failure.public_message.after",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "public_message",
            "value": observed["public_message"],
        },
        {
            "id": "approval-provider-failure.safe_server_diagnostic.after",
            "operation_id": "credential.approve",
            "case_id": "approval-provider-failure",
            "dimension": "safe_server_diagnostic",
            "value": observed["safe_server_diagnostic"],
        },
    ],
}
sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
