Approved maintainer decision: first regression enrollment

Problem
The current contract requires an applicable production change to use a behavior
catalog already present at its immutable base. It also classifies the first
catalog and producer workflow as production-affecting. ElevenID/.github has no
such catalog or producer trio at main 795728a954ca67d841054a5860af30b00c25276f.
Independent review therefore cannot produce passing evidence for PR75 by
retrofitting files into its head. Its green CI and resolved security finding do
not satisfy this missing requirement.

Decision
An authorized policy maintainer permits one separate, independently reviewed,
source-free enrollment change for ElevenID/.github to establish its initial
regression catalog, caller, harness and subject on protected main. That change
must identify itself as first enrollment with missing pre-change artifacts; it
must not claim ordinary passing applicable evidence or use not_applicable.
The maintainer decision and exact-head independent review are recorded publicly
before its normal protected merge. Required CI, merge queue, linear history and
all other branch protections remain enforced.

The enrollment change may add only the public-source regression inventory,
credential-free baseline producer and validation/tests needed to capture the
repository's existing behavior. It must not alter existing operational behavior,
grant secrets, admit private sources or runtime images, enable repositories,
publish restricted source, provision credentials, or activate a deployment.
The reviewer must verify these boundaries against the exact proposed tree.

After enrollment merges, capture the actual before artifact from that exact main
revision. Rebase the operational PR75 change onto this enrolled base and collect
its after artifact using byte-identical reviewed caller/harness/subject inputs.
Then satisfy the ordinary applicable evidence contract, independent exact-head
review and protected checks before operational integration. The one-time decision
does not waive PR75's ordinary evidence, future enrollment rules, live credential
qualification, source admission, signed release or deployment acceptance.

Commit certification must also be reconciled according to CONTRIBUTING.md before
merging; preserve current published refs, evidence and source hashes, and renew
exact-head review bindings if commit identities change.

Authorization
The maintainer approved this specific decision and delegated independent Codex
review, including re-reviews, on 2026-11-24 in the deployment goal thread.
The approval permits the separate enrollment change only; PR75 still needs
ordinary applicable evidence after rebase onto the enrolled baseline.
