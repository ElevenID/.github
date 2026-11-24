# Proposed maintainer decision: reviewer case identity bootstrap

**Status: proposed; maintainer approval has not been recorded.**

## Current contract defect

The approved reviewer implementation `41ce275e615b9ca9be11fde292e6d3b84c8b8ef5`
rejects two different cases that share their catalog operation's human name.
The protected-main behavior catalog at `beb11758046de8fb6ca75b1216ada6830f1a137b`
legitimately groups multiple cases under each operation. The current subject
does not call the affected `_validate_operations` branch. The ordinary
phase-bound review therefore cannot truthfully qualify this repair using
the old approved implementation and byte-identical old/new subject inputs.
No `not_applicable` or fabricated preserved disposition resolves this defect.

## Bounded bootstrap requested

Permit one separately reviewed, source-free policy change to add four fixed
reviewer operation/case identity observations and repair only the validation
of repeated human names across distinct cases. The repair must continue to
reject duplicate case IDs, two operation IDs sharing a name, and one operation
ID changing names. This is a review-contract repair, not an authorization to
admit source, publish a runtime, enable a repository or deploy a service.

The candidate must preserve every one of the existing 68 cases and 204
observations. Its subject, caller and catalog must be internally bound by
exact hashes, and its new cases must be executed against both the old reviewer
and the repaired reviewer in isolated Linux. Independent review must inspect
those actual results and the exact candidate tree. Required CI, CodeQL,
conversation resolution, linear history and the protected merge queue remain
in force. The reviewer must record that this is a bounded bootstrap exception,
not ordinary passing applicable evidence.

After a protected merge, the new main push must produce its real before
artifact. A separately reviewed activation change may set
`maintenance/feature-regression-approved-revisions.json` to the exact merged
reviewer implementation revision while keeping `enabled_repositories` empty.
That activation requires its own exact-source review and normal protected
checks; no guessed pre-merge SHA or broad revision allowance is authorized.

PR #75 must then rebase onto that enrolled and activated base, produce a fresh
after artifact with byte-identical producer inputs, and satisfy ordinary
marked evidence. The 70 changed dimensions still need separately approved
intentional-change records already present at its immutable base. This
decision does not approve those records, private credentials, runtime
publication, Supabase migration, Rifare or production cutover.
