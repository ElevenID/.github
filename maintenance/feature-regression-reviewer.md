# Feature-Regression Reviewer contract

The Feature-Regression Reviewer is a required role in ElevenID's self-review
loop for migrations, rewrites, ownership transfers, large refactors, and code
deletions. Its purpose is to find behavior that compilation, route inventories,
line counts, and happy-path tests do not prove was preserved.

A large refactor is any change that replaces a production behavior owner,
changes a public or internal contract, deletes executable code or deployment
wiring, or makes parity depend on a different language or repository. Every
pull request records either `applicable` or `not_applicable`; the latter requires
a concrete rationale and empty operation and disposition lists.

The reviewer is independent of the implementation pass. It begins read-only,
reviews the exact proposed head, reports findings before summaries, and does not
approve based only on the new implementation's tests or documentation.
The reviewer's named context must differ from the implementation context. The
same maintainer may run both passes only through separately identified contexts;
changing a label without starting a fresh, read-only review does not satisfy the
contract.

## Required evidence

The reviewer derives the pre-change behavior inventory from authoritative
sources that existed before the change:

- production source and configuration;
- public and internal API contracts;
- tests, fixtures, demos, runbooks, and released behavior;
- callers, downstream consumers, persistence schemas, and deployment wiring;
- repository history when code was previously removed, disabled, or moved.

New tests are evidence about the replacement, not evidence that the inventory
is complete. When behavior crosses repositories or languages, the review must
use one language-neutral JSON contract and exact repository/path/commit tuples
that the gate can fetch. The gate computes the declared common digest with
`elevenid-deterministic-json-v1`; raw file hashes are not accepted.

## Mandatory review surface

For every changed or retired capability, compare old and new behavior across:

1. route, command, event, job, and library entry points;
2. request fields, defaults, validation order, normalization, and bounds;
3. success status, response fields, ordering, side effects, and idempotency;
4. failure status and exact user-visible error meaning, including operation-
   specific wording such as approval versus issuance;
5. persisted state, transactions, audit events, reconciliation records, and
   recovery metadata;
6. metrics, counters, structured logs, and safe operator diagnostics;
7. authentication, tenant isolation, redaction, and secret-handling behavior;
8. dependency failure, timeout, malformed input, partial failure, retry,
   concurrency, and degraded-mode behavior;
9. configuration, startup checks, deployment selectors, rollback paths, and
   downstream consumers;
10. tests and demos that prove the behavior through the production boundary.

Raw secrets, provider payloads, URLs containing credentials, authorization
headers, and personal data must not be preserved merely for parity. When a
public diagnostic is correctly redacted, the reviewer must verify that a safe
server-side category or stage remains observable without sensitive detail.

## Deletion and migration rules

Every deleted behavior must have a traceable disposition:

- **preserved**: identify the exact regression evidence;
- **moved**: identify the new owner and exact parity test;
- **intentionally changed**: document the decision, compatibility impact, and
  replacement behavior;
- **unreachable**: prove there are no runtime, test, deployment, or downstream
  consumers;
- **lost**: block the pull request until restored or reclassified as an
  intentionally changed breaking loss.

An intentionally changed breaking loss requires a pre-existing immutable JSON
decision in the reviewed repository at `reviewed_base`. A pull request cannot
self-authorize feature loss by adding its own decision at `reviewed_head`. The
record binds the exact operation/dimension or behavior, before/after JSON values
and SHA-256 digests, compatibility impact, replacement, breaking-loss flag, and
approver. Evidence selects it with
`decision:<owner/repo>@<reviewed_base>:<path>#<id>`. The approver must post the
evidence comment, `approved_by` must match that account, and GitHub must report
a consistent repository role: legacy `permission: write` with
`role_name: maintain` (or an equivalent `maintain`/`maintain` response), or
`admin`/`admin`. Self-declared roles, custom `write` roles, issues, discussions,
and the pull request itself cannot authorize the loss.

Every evidence comment, including `not_applicable`, must be posted by an account
GitHub reports as an owner, member, or collaborator.

File deletion, fewer lines, a green build, matching route counts, and absence
of imports are not sufficient evidence of feature parity.

## Review loop

1. Implement and test the proposed change.
2. Give the Feature-Regression Reviewer the exact base and head revisions plus
   related consumer/release revisions.
3. The reviewer performs a read-only comparison and reports findings with
   severity, old/new evidence, affected behavior, and the missing test.
4. The implementer corrects all blocking findings and adds regression tests.
5. The reviewer repeats the full affected-surface review on the corrected exact
   head; reviewing only the corrective diff is insufficient.
6. The reviewer posts a new machine-readable evidence comment for the corrected
   exact head. The latest marked comment from an authorized owner, member, or
   collaborator is authoritative; an older passing comment cannot approve a
   later push, and an outsider cannot override authorized evidence.
7. Merge only when the evidence gate reports no unresolved blocking finding and
   all protected checks pass.

## Reviewer output

The review comment or artifact must contain:

- exact repository, base revision, and head revision;
- findings first, ordered by severity, with file/line or runtime evidence;
- a behavior-disposition table for deleted or replaced capabilities;
- tests executed and important surfaces not exercised;
- explicit confirmation of response/error, persistence/audit, metrics/logging,
  security/redaction, configuration/deployment, and consumer coverage;
- remaining risks or a precise statement that no unresolved feature-loss
  findings remain.

The reviewer must not write "parity preserved" when evidence is indirect,
missing, or limited to a narrower layer than the behavior being claimed.

## Machine-readable evidence gate

Post a pull-request comment containing the marker below followed immediately by
a fenced `json` document. Start from the
[maintained evidence example](feature-regression-review-evidence.example.json).
The companion
[catalog](feature-regression-behavior-catalog.example.json),
[before artifact
observation](feature-regression-before-artifact-observations.example.json),
[after artifact
observation](feature-regression-artifact-observations.example.json), and
[decision](feature-regression-decisions.example.json) examples define the
strict versioned documents referenced by that evidence.
The catalog's sample digests bind the exact
[producer caller](feature-regression-observation-caller.example.yml),
[behavior subject](feature-regression-behavior-subject.example.py) and
[observation harness](feature-regression-observation-harness.example.py)
sources. Downstream repositories adapt the production import, cases, and tests,
then record the resulting raw-byte digests; they do not copy the sample values
as evidence for a different operation.
The artifact example's receipt hashes are the SHA-256 values of the example
subject's actual canonical standard output and empty standard error, and the
test suite reproduces both by executing that subject against a controlled probe.
The reviewer login in the document must match the authorized GitHub account that
posts the comment. The gate binds the attestation to fetched pull-request
metadata and tests its structure; it does not infer semantic parity. A separate
human or agent reviewer must still perform the read-only comparison.

````markdown
<!-- elevenid-feature-regression-review:v2 -->
```json
{ ...the evidence document... }
```
````

Every evidence document contains:

- exact `repository`, `reviewed_base`, and `reviewed_head` values;
- `inventory_sources` as repository/path/commit tuples explicitly marked
  `pre_change` or `post_change`;
- a `behavior_catalog` at `reviewed_base` for production-affecting changes;
- structured `findings`, sanitized one-line `commands`, strict `tests`,
  `unexercised_surfaces`, and `residual_risks`;
- `surface_coverage` with exactly the ten named contract surfaces from the
  maintained example; for an applicable production change every surface must
  contain strict evidence, never `not_applicable`; and
- `sanitized_public_evidence` must be `true`.

For an `applicable` review, `operations` contains every affected operation.
`public_status`, `public_message`, and `safe_server_diagnostic` each compare
structured `before.value` and `after.value` records with evidence on both sides.
A truly absent value is represented explicitly (for example, `"not_exposed"`)
with evidence; none of the three dimensions may be blanket `not_applicable` for
an applicable production change.
Each operation also carries stable operation and case IDs from the base behavior
catalog. The catalog maps production components to cases and every case declares
exactly `public_status`, `public_message`, and `safe_server_diagnostic` as its
invariant triple. The gate derives required cases mechanically from every
changed, deleted, or renamed production path and fails closed if a path is
unmapped or a derived case is absent.
A `preserved` or `moved` dimension must have equal values; `moved` also names the
new owner and maps the old and new tests. Any value difference must be
`intentionally_changed` with a linked decision, compatibility impact,
replacement behavior, authority, and breaking-loss declaration.

`behavior_dispositions` accounts for each affected behavior as `preserved`,
`moved`, `intentionally_changed`, or `unreachable`. A moved behavior has a new
owner and old/new test mapping. An intentional change carries the same decision
record required for an operation difference. Any blocking finding must be
resolved.

Evidence references use only these forms:

- `test:<owner/repo>@<40-character commit>:<repository-relative path>::`
  `<test token>`; or
- `artifact-observation:<owner/repo>@<run id>:<observation id>`; or
- `artifact:https://github.com/ElevenID/<repo>/actions/runs/<numeric id>`.

Test references must point to a recognized test path. Top-level tests, surface
coverage, behavior evidence, and production-boundary runs bind to
the current repository at `reviewed_head`. A moved-test `before` reference may
bind either to the current repository at the immediate `reviewed_base` or to an
exact `pre_change` inventory tuple. Its `after` peer may bind either to the
current repository at `reviewed_head` or to an exact `post_change` inventory
tuple. Repository, path, commit, and phase are all authoritative; unlisted
substitutions fail closed. Artifact `producer_test` references are stricter and
must remain in the artifact's own repository at its exact observed commit.
Production-boundary coverage must
include a completed successful Actions run whose `head_sha` is `reviewed_head`.

Operation snapshots do not accept arbitrary test names as proof of values.
Both phases select immutable GitHub Actions artifacts containing canonical
`elevenid.behavior-observations/v3` JSON. A `before` artifact must come from a
successful `push`, `schedule`, or `workflow_dispatch` run on `main` whose
`head_sha` is exactly `reviewed_base`; an `after` artifact must come from a
successful `pull_request` run whose `head_sha` is exactly `reviewed_head`.
Checked-in observation JSON is not accepted: requiring such a file to contain
its own future commit SHA creates an impossible fixed point.

The base catalog, observation harness, and behavior subject must live below the
reserved `.github/feature-regression/`
governance path. A change to any file below that path, or to the producer
workflow, is production-affecting and cannot use `not_applicable`. This prevents
a docs/test-only pull request from weakening the trusted base for the next
migration.

The base catalog declares the exact producer caller workflow path and raw-byte
SHA-256; the pinned central producer workflow commit; the harness and subject
paths and raw-byte SHA-256 digests; the subject runtime, fixed arguments, and
non-secret fixed environment; the OCI runtime image pinned with an immutable
`@sha256:<64 hex>` digest; the successful job and exact atomic-producer and
upload step names; the artifact-name prefix; and the sole JSON member path. The
gate fetches the producer caller, harness, and subject at
`reviewed_base` and `reviewed_head`, requires every pair to be byte-identical,
and checks all catalog digests. The caller must be the gate's exact single-job
template invoking
`ElevenID/.github/.github/workflows/feature-regression-observation-producer.yml`
at the same approved feature-implementation commit used by the review gate;
extra steps or jobs are rejected. This feature-implementation pin is distinct
from the newer Organization Quality policy pin that authorizes it.

The pinned central producer checks out the target head without persisted
credentials and checks out its standard-library runner from that policy commit.
The runner verifies that the pinned harness and subject are regular,
non-symlink files with the catalog digests. One trusted host process performs
the entire operation. Subject and harness code run only in the catalog-pinned
OCI image through `docker run --rm --pull=missing`, never as host children. Each
container has a private PID namespace, no network, an unprivileged user, a
read-only root filesystem, a bounded `noexec,nosuid,nodev` `/tmp`, all
capabilities dropped, `no-new-privileges`, and fixed PID, memory, and CPU limits.
The target checkout is mounted read-only at `/workspace`; no Docker socket,
host PID namespace, trusted temporary directory, capture file, harness-output
file, or final artifact path is passed or mounted separately. The unique
container is forcibly removed on every success, failure, timeout, or output-
bound path. Container lifecycle termination therefore removes detached or
`setsid()` descendants before trusted publication.

The subject receives closed standard input, fixed arguments, and an allowlisted
environment, and must emit bounded canonical
`elevenid.behavior-subject-output/v2` JSON on standard output. The host runner
keeps the resulting capture and receipt only in memory. It pipes canonical
capture JSON to separately isolated harness test and emit containers through
standard input; the emit result returns through bounded standard output. No
untrusted container can see a host capture path, harness-output path, or output
argument. The runner requires every emitted identity and value to match the
in-memory subject output. The harness can attach only a recognized exact-head
producer-test reference; it cannot author or replace the invocation receipt or
producer provenance. The host injects those fields, revalidates the canonical
v3 document in memory, and atomically publishes it only after every container
has exited and been removed. No later command or workflow step reloads a
persisted capture as trusted input. The GitHub job record must contain the
catalog-declared atomic producer and upload steps exactly once, both completed
successfully. A recognized test name, a hand-authored head JSON, a detached
descendant, or a capture modified between workflow steps cannot substitute for
this chain.

The artifact name is
derived as `<prefix>-<run id>-<run attempt>` so a stale rerun artifact cannot be
selected. The gate uses GitHub API version `2026-03-10`, requires the exact-head
run and attempt, validates the declared successful job by run ID and head SHA,
requires one unexpired artifact whose mandatory `workflow_run` metadata exactly
matches the run, head SHA, head branch, repository ID, and head-repository ID
and whose API-provided SHA-256 digest is present, downloads
it without forwarding authorization to artifact storage, and verifies that
digest. The bounded ZIP must contain one regular, unencrypted member at the
declared path. Its strict JSON must already be in
`elevenid-deterministic-json-v1` canonical form and echo the exact workflow,
job, artifact, run, attempt, and head provenance. Every observation binds the
operation/case/dimension/value and a recognized exact-head producer test.
These structural checks prove execution and value flow, but cannot prove the
semantic relevance of arbitrary code. The independent reviewer remains
responsible for operation/catalog completeness and for confirming that the
baseline subject actually exercises the claimed production boundary and derives
its output from runtime behavior. The reviewer must reject a no-op, obfuscated,
or hard-coded subject and a no-op or misleading harness even when its structure
passes the machine checks.

For `not_applicable`, give a concrete rationale and use empty `operations` and
`behavior_dispositions` arrays. The validator obtains the complete changed-file
metadata and allows this decision only for obvious documentation/test-only modifications.
Source, configuration, contracts, deployment, workflows, executables, any
deletion or rename, an empty file list, and any uncertain classification force
`applicable`.

## Cross-boundary digest method

When `cross_boundary.applies` is `true`, provide at least two unique
repository/path/commit tuples.
Every tuple must also appear in `inventory_sources`, and the set must contain
the current repository at `reviewed_head`. Cross-boundary evidence is mandatory
when inventory spans repositories, any inventory source differs from the current
repository, or any behavior/dimension moves to another repository; all named
external owners and every repository represented in inventory must have at
least one exact canonical contract tuple in `cross_boundary.sources`. Inventory
may also name legacy Python, test, configuration, or other non-JSON sources;
those sources remain exact provenance but are not forced into digest
equivalence. This separation allows a legacy implementation and a frozen JSON
contract to coexist without pretending their bytes have the same meaning.
The canonical current-repository contract at `reviewed_head` must be declared as
a `post_change` inventory source; a `pre_change` label cannot substitute for the
reviewed result. Repository names are compared case-insensitively when enforcing
source uniqueness.
Every source declares the same
`sha256:<64 lowercase hex>` value as `common_sha256`. The gate fetches every
file from the GitHub contents API at that exact commit and compares its computed
digest.

`elevenid-deterministic-json-v1` is the reference method implemented by
`scripts/feature_regression_review.py`:

1. decode strict UTF-8;
2. parse JSON while rejecting duplicate object keys and non-finite constants;
3. serialize with Python's standard-library `json.dumps`, `ensure_ascii=False`,
   `sort_keys=True`, `separators=(",", ":")`, and `allow_nan=False`;
4. hash the resulting UTF-8 bytes with SHA-256; and
5. prefix the lowercase hexadecimal result with `sha256:`.

This is an explicitly versioned ElevenID method, not a claim of RFC 8785
compliance. A caller repository's standard `GITHUB_TOKEN` cannot read private
sibling repositories. Such a cross-private-repository review fails closed until
an organization-managed, read-only contents credential or required-workflow
facility is deliberately provisioned; do not weaken or bypass the digest.
Likewise, exact Actions runs and collaborator-permission resolution are read-only
API calls but may be denied to a default caller token, especially across private
repositories or when repository administration metadata is restricted. The gate
fails closed in that case; activation must provision only the minimum read access
needed for contents, Actions metadata, and collaborator permission lookup.

The public evidence contains sanitized conclusions, test names, and safe
artifacts only. Inspect private production source and configuration in an
authorized environment, but never paste private source, secrets, raw provider
payloads, credential-bearing URLs, authorization headers, personal data, or
sensitive logs into a public comment or artifact. The validator recursively
rejects control characters/newlines, authorization and Bearer values, common
and generic token/secret/private-key assignments, private-key blocks,
standalone PAT/API-key prefixes such as `ghp_`, `github_pat_`, `sk-`, and
`xox*`, quoted JSON/YAML secret assignments such as `"password":"..."` or
`authorization: "Basic ..."`, email- or phone-shaped personal data, and URLs
containing userinfo, parameters, queries, fragments, or secret-like path
segments after repeated percent-decoding.
Evidence JSON rejects
duplicate keys and non-finite constants.

The dependency-free validator checks the latest marked comment against fetched
pull-request metadata and files. On `merge_group`, it binds `reviewed_base` to
the actual merge-group base, compares the group base and head, discovers the
head-ref PR plus every open PR associated with the group head and intervening
commits, and validates each PR's own head and evidence. It fails if the comparison
is truncated. This is required because ElevenID merge queues can build multiple
entries together. Discovery uses GitHub's head-ref, compare, and associated-PR
APIs and fails closed on truncation; it cannot independently prove that GitHub
did not omit an association from all of those API responses. Semantic operation
and inventory completeness therefore remain the human/agent reviewer's
responsibility, not a claim made by the structural gate.

Repositories install `.github/workflows/feature-regression-review-caller.yml`
to call the organization reusable `.github/workflows/feature-regression-review.yml`
from both
`pull_request` and `merge_group` with `actions: read`, `contents: read`,
`issues: read`, and `pull-requests: read`. Pin the reusable workflow and literal
`policy-ref` to the same full approved feature-implementation commit, which
must equal the Organization Quality policy checkout's singular trusted
`approved_revision`. This is not the Organization Quality policy checkout's
own commit. Local, dynamic, branch, tag, unapproved, and mismatched calls are
prohibited. Never use `pull_request_target`. After posting or replacing
evidence, rerun the current head or merge-group gate; a comment intentionally
does not start a privileged workflow.

Use a caller shaped like this, replacing both occurrences of
`APPROVED_FEATURE_IMPLEMENTATION_SHA` with the same reviewed 40-character
feature-implementation commit:

```yaml
name: feature-regression-review

on:
  pull_request:
    branches: [main]
  merge_group:
    types: [checks_requested]

permissions:
  actions: read
  contents: read
  issues: read
  pull-requests: read

jobs:
  feature-regression-review:
    uses: ElevenID/.github/.github/workflows/feature-regression-review.yml@APPROVED_FEATURE_IMPLEMENTATION_SHA
    with:
      policy-ref: APPROVED_FEATURE_IMPLEMENTATION_SHA
```

This is an exact caller schema, not a sketch. The filename must be
`.github/workflows/feature-regression-review-caller.yml`; `pull_request`
targets only `main` without `types` or `paths` filters; `merge_group` uses only
`checks_requested`; permissions, the single `feature-regression-review` job,
`uses`, and `policy-ref` must match exactly. `if`, `needs`, `continue-on-error`,
strategy/matrix, extra jobs, and other skip or masking controls are prohibited.
The protected context is exactly
`feature-regression-review / Feature Regression Review`.

## Bootstrap and activation rollout

The policy repository cannot safely call an unmerged local or dynamic copy of
its own gate during the bootstrap pull request.

The deployable rollout deliberately has two different immutable pins:

- `APPROVED_FEATURE_IMPLEMENTATION_SHA` is the merge commit containing this
  v2/v3 repair. The Feature Regression reviewer, observation producer, their
  `policy-ref` values, and each behavior catalog's `central_workflow_sha` use
  this commit.
- `QUALITY_POLICY_SHA` is the later activation commit whose singular
  `approved_revision` equals `APPROVED_FEATURE_IMPLEMENTATION_SHA`.
  Organization Quality uses this later commit and passes it as `policy-ref`.

The historical activation commit
`0ce5534d83c050166b706b93bed31d0e6c214ca8` still approves the legacy
implementation `cdecf65ee23c9969f49f61e8d4a0946c95ab4bec`. That implementation
does not accept the v2/v3 phase input and cannot produce an exact-base artifact.
It must be rejected for a v2/v3 installation, not treated as a downgrade path.

The maintained catalog, caller, and artifact examples use
`eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` as an obvious fail-closed sentinel
for the not-yet-known repair merge SHA. Never deploy that sentinel. After the
repair and its separate activation merge, replace every sentinel and every
`APPROVED_FEATURE_IMPLEMENTATION_SHA` placeholder with the singular approved
repair SHA. Replace each `QUALITY_POLICY_SHA` with the later activation SHA.
Do not collapse the two pins or substitute the quality-policy commit into a
Feature Regression caller.

1. Merge this reviewed repair while `enabled_repositories` remains empty and
   the live catalog remains unchanged. This merge creates the immutable value
   for `APPROVED_FEATURE_IMPLEMENTATION_SHA`.
2. In a separate policy-only activation change, replace the catalog's one
   `approved_revision` with the repair merge SHA. Keep `enabled_repositories`
   empty. The activation merge becomes `QUALITY_POLICY_SHA`; never retain the
   legacy and repaired revisions as parallel selectable options.
3. In each target repository, first land its exact observation-producer caller
   plus v3 base behavior catalog, immutable harness, and immutable behavior
   subject in `.github/feature-regression/` as a separate protected change. Do
   not check in a `before` observation fixture. The producer caller's `uses`
   and `policy-ref`, and the catalog's `central_workflow_sha`, all use
   `APPROVED_FEATURE_IMPLEMENTATION_SHA`.
4. Let the merge's `push` run create the exact-main `before` artifact. The
   weekly schedule and a manual dispatch on `main` refresh baseline artifacts,
   which are retained for 90 days. If the exact PR base artifact has expired,
   refresh only while that commit is still current `main`; otherwise update the
   PR base and generate a new exact baseline. Never substitute a nearby run.
5. In a later protected pull request, add the reserved review caller above and
   update that repository's Organization Quality reusable workflow and its
   `policy-ref` to `QUALITY_POLICY_SHA`. These two pin pairs must not be
   collapsed into one value. The distinct caller and reusable filenames allow
   ElevenID/.github to host both without self-reference or filename collision.
   A migration cannot claim coverage by introducing its catalog in the migration
   head; changed production paths without a catalog at `reviewed_base` fail.
6. Exercise `pull_request`, baseline `push`/`schedule`/manual refresh, and
   multi-entry `merge_group`.
7. In a central policy follow-up, add the repository name to
   `enabled_repositories`. Because Organization Quality checks out an immutable
   policy commit, the target repository must then update its Organization
   Quality `uses` and `policy-ref` to that later merged enablement commit. Until
   that pin update lands, the target still reads the earlier empty activation
   list; merely changing the central default branch does not activate
   enforcement.
   After the pin update, workflow policy fails if the reserved exact caller is
   deleted, omitted from the scan, or replaced by a lookalike. The policy
   command requires the current repository through `--repository` or
   `GITHUB_REPOSITORY` and fails closed if it is absent.
8. Require the exact
   `feature-regression-review / Feature Regression Review` context in branch
   protection. Finally prefer an organization ruleset-required workflow so a
   repository cannot remove or spoof its caller.

Rust repositories require an additional prerequisite. The present producer
intentionally provides a 30-second, 256 MiB, read-only `/workspace` and a small
`noexec` temporary filesystem. That isolation cannot honestly compile and run a
real Rust candidate probe, and a hard-coded Python or no-op subject is not an
acceptable substitute. Do not add a Rust repository to `enabled_repositories`
until a separately reviewed design supplies a bounded writable executable build
tmpfs and a digest-pinned offline Rust runtime without weakening the existing
network, credential, namespace, or provenance constraints.
