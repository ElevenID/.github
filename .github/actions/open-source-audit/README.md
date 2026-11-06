# Open-source policy audit

The action checks repository licenses, prohibited private billing markers,
stale repository references, pinned Actions, and runner/event boundaries.
It also parses workflow YAML with duplicate-key rejection. The action installs
the same pinned PyYAML version used by the shared workflow-quality job.
Failures retain a nonzero exit status and print a fixed message. CI output does
not reproduce findings or parser source snippets that could contain literal
credentials in malformed input.

## Reviewed dependency fetches

The general prohibition on repository secrets in pull-request workflows remains
in force. One constrained source-reader pattern is recognized for the four
explicit consumer repositories in `private_forks_policy.py`. A secret name by
itself does not grant an exception.

Every recognized reader call must have a prior credential-free trust check that
runs whenever the reader is active. Checks cannot ignore failure, execute an
unreviewed command, or use a narrower condition than the reader. Status-function
conditions that override normal step success ordering are rejected. The reader
cannot appear in a workflow/job environment or be passed to compilation, tests,
an arbitrary action, or an arbitrary shell command.

Host calls may only invoke the reviewed helper's locked fetch command, or its
existing six-package update command. The helper's SHA256 is verified without
executing it during the audit. That reviewed helper rejects external and
Dependabot pull requests, verifies internal PR and merge-group context, limits
Git credentials to the approved HTTPS host/repository paths, and leaves no
persisted reader configuration. Changing those runtime rules requires an
explicit policy update and review.

BuildKit calls must use the pinned build action or reviewed composite action,
the dedicated fetch secret, and the matching nonsecret mode argument. Reviewed
Docker secret-handling files are checked by SHA256. Intermediate build targets,
reader build arguments, private-mode cache exports, and build-record exports
are rejected. The product composite limits its reader to native matrix rows.

All other repository-secret references in PR workflows remain prohibited,
including bracket notation and conditional expressions. Existing unrelated
secrets in non-PR release workflows retain their prior treatment. The
`pull_request_target`, self-hosted fork runner, license, private billing marker,
and action-pinning checks are retained.

This validates a reviewed workflow structure; it does not make arbitrary
repository code safe to run with source access. Repository write access and
merge admission must remain limited to contributors entitled to the sources.

## Validation

Run `python -m unittest discover -s tests -p test_private_forks_policy.py` from
the repository root. The fixtures retain actual reviewed reader/trust steps
and event conditions from all four consumer repositories, with their source
commit identifiers. Unit fixtures use stand-in file contents to test digest
enforcement. Integration validation separately runs the auditor against the
actual consumer trees and actual reviewed file hashes.

Do not automatically refresh the helper or Docker hashes when a test fails.
Review the changed runtime access boundary and its tests first, then update the
policy and consumer pin through the normal review process.
