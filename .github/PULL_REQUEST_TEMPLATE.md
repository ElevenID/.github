# Pull request

## Summary

<!-- What changes, and why? -->

## Validation

<!-- Commands, checks, or manual scenarios run. -->

## PR feedback

Follow the [central ElevenID contribution policy](https://github.com/ElevenID/.github/blob/main/CONTRIBUTING.md),
including `maintenance/pr-feedback-resolution.md` in that repository.

- [ ] Every substantive human and automated comment has a documented fix or
      reviewer-accepted disposition.
- [ ] Fixes were verified on the corrected head, and applicable reviews were
      repeated after relevant changes.
- [ ] All review conversations are resolved; no general comment raises an
      unanswered or uncorrected issue.

## Feature-regression review

Follow the visible
[Feature-Regression Reviewer contract](https://github.com/ElevenID/.github/blob/main/maintenance/feature-regression-reviewer.md).
The gate reads the latest separately posted comment containing
`<!-- elevenid-feature-regression-review:v2 -->`.

- [ ] Applicability is declared with a concrete rationale in the evidence.
- [ ] A reviewer in a fresh context independent of the implementation pass
      compared the exact repository/base/head against authoritative inventory
      sources, then reported findings first.
- [ ] All ten contract surfaces have exact evidence; production-affecting
      applicable reviews do not use blanket N/A.
- [ ] Every affected operation compares before/after public status, public
      message, and safe server diagnostics with downloaded immutable v3
      artifacts for both the exact base and exact head.
- [ ] Every changed production path maps to a stable base-catalog case and its
      exact invariant triple.
- [ ] The base catalog, behavior subject, harness, and producer caller are
      anchored below the reserved governance paths, byte-identical at
      base/head, and both observation phases came from the pinned central runtime
      producer's digest-pinned isolated containers and atomically published,
      host-runner-owned in-memory capture.
- [ ] Every deleted or replaced behavior is traced to a tested new owner, or an
      authorized intentional-change decision and compatibility impact.
- [ ] Reviewer findings were corrected and the reviewer repeated the review on
      the corrected exact head.

Latest machine-readable evidence comment:

## Public repository checklist

- [ ] No credentials, customer data, private source, payment-provider config,
      or commercial pricing is included.
- [ ] Tests and documentation are updated where needed.
- [ ] Commits include a DCO `Signed-off-by` trailer.
