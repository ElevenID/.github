# PR feedback resolution

Every PR comment from a person or automated reviewer must be examined before
merge. A passing check or later approval does not erase a reported defect.

## Required merge state

- Enable GitHub's **Require conversation resolution before merging** setting
  on every branch that accepts PR merges. Do not bypass the rule, including
  for administrators or merge-queue entries.
- If a repository's GitHub plan does not support this protection, record the
  missing technical gate and enforce this policy during human merge review.
  Do not describe an unchecked branch as protected.
- Resolve every review conversation only after its concern is corrected and
  verified, or after the reviewer accepts an evidence-backed explanation that
  no change is needed. A reply alone is not a fix.
- General PR comments have no review-thread resolution control. Reply to each
  substantive comment with its disposition and the relevant commit, test, or
  decision link. Informational status messages need no reply. Do not merge
  while a general comment still raises an unanswered or uncorrected issue.

## Development response

1. Read all current review threads, general comments, security findings, and
   failed checks. Identify each distinct issue and whether it still applies to
   the current head. Do not assume an outdated line or a merged PR means the
   underlying issue is fixed.
2. Reproduce valid findings, correct the underlying behavior on the PR branch,
   and add or update focused regression coverage when it protects a real risk.
   Update affected documentation and contracts as needed.
3. Run the focused check and affected repository gates against the combined
   corrected head. Record commands, results, and any unavailable checks.
4. Reply to each substantive finding with the fix and verification evidence.
   For a false positive or proposed deferral, explain the evidence and obtain
   reviewer agreement before resolving the thread. Keep a real unresolved
   concern open until a correction or accepted decision exists.
5. Re-run applicable independent reviews after relevant changes. Before merge,
   inspect the PR again for new comments, unresolved conversations, required
   checks, and exact-head review evidence.
