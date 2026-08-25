# Wave-three post-migration cleanup

Status: Active  
Opened: 2026-08-25  
Production posture: No production deployment or production-state mutation

## Objective

Close the remaining retirement and hygiene work after the wave-three Rust
migration without removing supported behavior. Prefer shared Rust crates and
DRY implementations. Any supported Python behavior must have a
language-neutral contract and passing Rust parity tests before its Python path
is removed.

This is a cleanup objective, not a reopening of the completed aggregate
migration. A remaining Python or MMF reference is evidence to classify, not
proof that the production path still uses it.

## Current evidence

The 2026-08-25 inventory found several repositories whose current metadata can
still make retired Python MMF paths appear supported. Cleanup is now tracked by
the following governed changes:

- `marty-credentials` declares the released `marty-msf` wheel and retains an
  MMF migration-adapter import. Pull request
  [marty-credentials#201](https://github.com/ElevenID/marty-credentials/pull/201)
  removes both while preserving the adapter behavior through the released
  shared `marty-common` implementation. Its full Python gate exposed and then
  verified the newly explicit `python-multipart` dependency that had previously
  arrived transitively through `marty-msf`.
- [marty-core#250](https://github.com/ElevenID/marty-core/pull/250) adds a
  language-neutral biometric behavior contract and passing Rust parity tests.
- [marty-integration-tests#391](https://github.com/ElevenID/marty-integration-tests/pull/391)
  deletes the direct Python MMF biometric test after that Rust gate passed and
  adds a negative policy test preventing the dependency from returning.
- [product-catalog#6](https://github.com/ElevenID/product-catalog/pull/6) is
  merged and now describes the Rust crate platform as current and the Python
  distribution as retired compatibility history.
- [Marty#63](https://github.com/ElevenID/Marty/pull/63) is merged. An
  organization-wide symbol search proved that the released credential KMS
  adapter had no consumer, while current signing-key behavior is owned and
  tested by the Rust signing-keys service and shared crates. The pull request
  removed 786 lines and added a negative source-ownership gate.
- [Marty#64](https://github.com/ElevenID/Marty/pull/64) is merged. It removed
  the unreachable 5,562-line Python notifications package after the canonical
  `mmf-push`, Rust notification, and Rust device-registration contract suites
  passed.
- [Marty#65](https://github.com/ElevenID/Marty/pull/65) is merged and retires
  the unconsumed
  root Python MMF plugin entry point and health-only artifact. It removes the
  root image/release pipeline and exact Docker, Compose, Helm, Kubernetes,
  demo, and stale documentation surfaces while retaining `marty-common` and
  compatibility code still under audit.
- [Marty#66](https://github.com/ElevenID/Marty/pull/66) is merged and removes
  the remaining
  consumer-zero Python configuration and observability adapters that import
  the old top-level `framework` package. AST policy gates now prevent imports
  rooted at `framework`, `mmf`, or `marty_msf` from returning in Marty source
  or the released `marty-common` package.
- [marty-microservices-framework#94](https://github.com/ElevenID/marty-microservices-framework/pull/94)
  freezes the legacy Python distribution, disables future Python release/tag
  workflows, marks its package inactive, and names the 18-crate Rust workspace
  as canonical. The Python source and `v1.0.2` evidence remain until the final
  consumer and backup gates pass.
- [marty-ui#612](https://github.com/ElevenID/marty-ui/pull/612) labels the sole
  remaining tracked `marty-ui` Python MMF snippet as a superseded historical
  migration record, not a supported runbook.
- [marty-ui#613](https://github.com/ElevenID/marty-ui/pull/613) restores the
  shared fail-closed release-environment preflight that an open-source release
  rewrite had accidentally disconnected. It gates stack release, beta
  lifecycle, and wallet conformance using only read-only workflow-token access.
- `Marty` and `marty-credentials` are active mixed-language repositories and
  are not archive candidates while they own supported artifacts.

Pull requests 201, 250, 391, 94, 612, 613, and this governed document are
configured for automatic merge but still require one independent reviewer under
protected-branch rules. `burdettadam` cannot self-approve, and the only other
write-capable identity discovered is the explicitly disallowed historical
account. Branch protections remain intact while an approved independent
reviewer is arranged. The first six pull requests have passing required checks;
pull request 613 is running its protected CI matrix.

These references may be compatibility, historical, test-only, or obsolete.
They must be classified before a repository is archived or a path is deleted.

## Initial reference classification

- `marty-microservices-framework` is the active canonical Rust crate
  repository. Keep the repository and Rust releases; retire only its Python
  package after consumer proof.
- `marty-ui` is an active Rust consumer. Keep its Cargo pins, release inputs,
  and source references to the Rust `mmf-*` crates. Its one tracked Python MMF
  snippet is explicitly labeled historical by pull request 612.
- `marty-subscriptions` is an active self-host build consumer. Keep the
  canonical repository input while the build consumes its Rust crates.
- the Hermes workspace is a development and audit consumer. Keep the mount
  because it exposes the active Rust crate source.
- `marty-credentials` owns supported Python service images with Rust-backed
  domain operations. Remove the Python MMF wheel while preserving required
  adapter behavior; this is tracked by `marty-credentials#201`.
- `Marty` remains an active mixed-source compatibility repository, but its
  credential KMS and notifications paths are now retired by merged pull
  requests 63 and 64.
- `Marty/packages/marty-common/marty_common/crypto/credential_kms.py` was not a
  supported compatibility surface: no source or release consumer imported it,
  and `marty_common.crypto` did not export it. It was removed by pull request
  63 after confirming Rust signing-key ownership and passing package gates.
- `Marty/src/notifications` was isolated, never mounted by a runtime, and had
  no organization consumer. Its reachable behavior was already covered by
  language-neutral `mmf-push`, notification-service, and
  device-registration-service contracts. Pull request 64 removed it after all
  three Rust suites passed.
- `Marty/src/marty_plugin` still contains compatibility modules, but its
  package entry point and deployment artifact had no current consumer. The
  released image exposed only health/readiness endpoints and never mounted the
  four advertised service definitions. Pull request 65 retires that exact
  delivery surface without deleting retained passport-chip or identity code.
- `marty-integration-tests` has removed its direct Python MMF biometric test in
  pull request 391. Historical rewrite evidence remains intentionally retained.
- product catalog positioning is corrected by merged pull request 6.
- history and migration documents are evidence. Retain accurate records and
  label them historical instead of treating them as live dependencies.

Repository-name matches alone are not evidence of a Python dependency. The
consumer gate must distinguish Python package/import tokens (`marty-msf`,
`marty_msf`, and `mmf.*`) from valid Git and build references to the Rust crate
repository.

The operator-local inventory initially found approximately:

- 12.0 GiB of reproducible Rust build output under `.target`;
- 60 metadata-free worktree shells totaling 5.0 GiB;
- 6.7 GiB under `work`, mixing evidence with reproducible environments; and
- several same-origin, same-commit reference clones under `C:\w`.

The first generated-only cleanup tranche is complete. Cargo removed 35,948
files and 12.0 GiB from the verified workspace `.target` tree. A separately
allow-listed cleanup removed about 3.0 GiB of old snapshot `node_modules`,
snapshot-local PostgreSQL/Redis state, virtual environments, cargo homes, and
pytest caches. It retained acceptance reports, release evidence, wheels,
conformance checkouts, snapshot source, and all recovery bundles.

The refreshed Git inventory covers 24 canonical ElevenID repositories. Every
primary worktree is clean, with no stashes or special recovery refs. Its six
unmerged local branches correspond exactly to active protected pull requests
35, 94, 201, 250, 391, and 612; no orphan local branch remains.

Recovery evidence currently includes 41 verified Git bundles totaling
1,466,067,451 bytes. Every bundle passed `git bundle verify` again after local
cleanup. Those bundles are retained evidence, not disposable cache. The 41st
bundle preserves a unique OIDF 5.2.2 shell discovered after its linked
worktree owner had been removed. It records commit
`84179cb6a380b90505876c6c5636023bb24cb883`, tree
`31a90af0fb324ae894dfeb5c89240de23f39ce1a`, and SHA-256
`E50EFB932C18B760C536FAF0A65B4B8B8CE40C6D9E0AA25927BE857607EDC992`.
The original dead worktree pointer is retained beside the bundle.

The Marty recovery bundle was reverified before hosted release cleanup. Its
SHA-256 is
`BD460B770D24A92ECDAD535222854C5D512E93E4EE4A3B4E433FD15B73976A6B`, it
contains complete history, and it contains `refs/tags/v1.0.0` at
`d79ea0598982940d0720d81c2d6ed794b3bca046`. All 41 bundles now have a verified
second copy on physical disk 0 under an inheritance-disabled ACL limited to the
operator, local administrators, and SYSTEM. Every copied size and SHA-256
matches its manifest, and all 41 copies pass `git bundle verify`.

Before the approved hosted cleanup, all 11 Marty v1.0.0 release assets were
downloaded to both archives. They total 1,403,920 bytes, match the digests
reported by GitHub, and pass the release's `SHA256SUMS`. The GitHub release and
tag are now deleted. The obsolete `marty` image and `charts/marty` OCI packages
remain only because the current CLI credential lacks `delete:packages`; GitHub
rejected the request before deleting either package. Their exact version IDs
and digests are retained in both archives for a scoped retry.

A read-only hosted CI inventory found substantial artifact and cache metadata:
Marty 431/72, marty-core 2,795/11,675, marty-credentials 2,518/14,078,
marty-integration-tests 2,165/8, marty-ui 8,051/1,833,
marty-microservices-framework 136/16, and `.github` 8/4
(artifact records/cache records). The latest pages include release evidence,
SBOMs, security results, beta bundles, wheel matrices, Docker build records,
and reproducible compiler/image caches. Pruning therefore requires name,
workflow, age, and release-evidence classification rather than a bulk delete.

The first governed hosted-artifact cleanup removed 219 exact-name
`rust-db-test-bundle-1` records from `marty-ui`: 183 expired metadata records
and 36 completed-workflow intermediates totaling 34,734,864,000 live bytes
(32.35 GiB). The producer-to-consumer transfer now uses a zstd archive in
pull request 612. Its protected CI producer, download, extraction, database
contract, and service-test gates passed; the replacement artifact was
186,614,682 bytes, about 80 percent smaller than the previous transfer. That
completed-run intermediate was then deleted, leaving zero live artifacts with
the exact transient name. Release assets, beta evidence, wheels, SBOMs,
attestations, checksums, security results, and acceptance evidence were not
targeted. Current compiler and image caches are recent and remain useful to
the active pull requests, so they were retained.

The published-artifact scan found one live dependency that tracked-source
search could not close by itself. The latest `marty-credentials` release,
v0.1.68, declares the immutable `marty-msf` 1.0.2 wheel in its source archive,
and both its issuance and verification image SPDX inventories contain the
installed distribution. Pull request 201 removes the build input and now also
adds a normalized release-SBOM denylist validator. Its focused contract,
workflow, and startup suite passes 63 tests, and the validator rejects the
v0.1.68 SBOM as expected. A replacement credentials release must pass that
gate before v0.1.68 is historical and the Python framework can be archived.
No standalone MMF container package exists in the organization package
inventory, and the public PyPI JSON endpoints for `marty-msf` and
`marty-credentials` return 404; the GitHub release and credential images are
therefore the known published surfaces.

The last accepted beta rollback remains recoverable even though the approved
history rewrite intentionally removed the old `v1.1.194` tag and GitHub release
record. The four immutable OCI manifests recorded by the acceptance evidence
are still retrievable by digest. The archived release-evidence set contains the
stack manifest, three SBOMs, four Sigstore bundles, and `SHA256SUMS`; all nine
files passed a fresh checksum verification. Beta lifecycle run `31916804935`
and its 7,533,450-byte `mip-03-beta-credential-lifecycle` artifact remain live
through 2026-09-15. These are the retained rollback and acceptance floor until
a replacement stack release completes the final beta-only gate.

The live GitHub release-environment audit also found a protection regression:
the environment-policy validator and manifest remain tracked, but the
open-source release rewrite removed the validator's only workflow invocation.
Pull request 613 restores that gate. The live environments now disallow
administrator bypass and use explicit custom policies: `v*` tags for
`stack-release`, and `main` for `beta-lifecycle` and the newly created
`wallet-conformance` environment. The beta secret and variable inventories were
unchanged by that update. All three environments now fail the audit only because
no required reviewer is configured and self-review therefore cannot yet be
disabled. Selecting a new approved independent reviewer is an external
governance prerequisite and must not use a self-reviewing or explicitly retired
identity.

Local reference-clone reconciliation removed eight clean exact duplicates
under the workspace `work` directory and ten under `C:\w` only after matching
origin, commit, tree, and cleanliness. A remaining staged W3C checkout was
excluded from that deletion, traced to
[W3C PR 174](https://github.com/w3c/vc-data-model-2.0-test-suite/pull/174),
and removed only after its staged tree exactly matched hosted head
`ee3f93ce939161c889afd32591396473435c5ae7`; the clean canonical clone remains.
Fresh audits now report zero same-origin, same-commit, same-tree duplicate
groups in both roots. The duplicate reference cleanup reclaimed more than
3.7 GB, and removal of temporary tree-comparison repositories and indexes
reclaimed another 193,838,848 bytes. Together with the generated-output
tranche, confirmed local reclamation is more than 19 GB.

Metadata-free partial shells that do not exactly match an authoritative commit
remain retained evidence for at least one release cycle. They will be archived
individually before any later deletion. Recovery bundles, snapshots, and
conformance fixtures are treated as access-controlled internal artifacts
because they can contain historical configuration and test-key material.

## Execution backlog

### 1. Classify legacy references

- [x] Produce a repository-and-path inventory for every remaining Python MMF
  dependency, import, build context, workspace mount, test, and product claim.
- [x] Mark each tracked-source reference as supported runtime, supported
  compatibility, test-only, historical documentation, or obsolete.
- [x] Identify the owning Rust crate and language-neutral behavior contract for
  every supported runtime or compatibility capability.
- [ ] Confirm published artifacts and deployment manifests do not introduce
  additional consumers that source search misses.

  Current result: v0.1.68 credentials source and both service images are the
  final known published consumers. Pull request 201 removes and gates that
  dependency for the next release; this item remains open until the replacement
  release SBOMs pass and deployment inputs select those digests.

Current `Marty` path classification:

- `packages/marty-common/.../credential_kms.py` is consumer-zero obsolete code
  removed by merged pull request 63.
- `src/notifications` is consumer-zero obsolete code removed by merged pull
  request 64 after Rust contract and parity gates passed.
- the root `mmf.plugins` entry point, `MartyPlugin`,
  `modern_trust_anchor.py`, health-only image, and its release/deployment
  contexts were obsolete and were removed by merged pull request 65.
- `src/digital_identity` is retained compatibility source, not an MMF plugin or
  deployment owner. Pull request 65 removes its unused MMF-specific Redis
  factory and false production/migration documentation while keeping its
  generic cache and FastAPI registration behavior.
- hidden legacy framework imports in configuration and observability modules
  under `marty-common` and `marty_plugin` were consumer-zero and are removed by
  pull request 66. The inlined Alembic migration adapter retains only an
  explicit historical attribution and has no Python MMF dependency.
- `packages/marty-common`, excluding classified compatibility paths, is an
  active released shared library and must be retained.
- the only `marty-ui` Python MMF match is a superseded migration snippet. Pull
  request 612 adds an explicit historical warning without changing runtime
  behavior.
- outside the canonical framework repository, current tracked-source matches
  are now limited to negative gates, changelog/history, inlined attribution,
  the frozen-wheel catalog record, and the two explicitly historical guides.

### 2. Preserve behavior and remove obsolete code

- [ ] Add or strengthen contract and negative-path tests before changing each
  supported behavior.
- [ ] Port supported behavior to the shared Rust crate platform, reusing
  existing abstractions instead of adding consumer-specific copies.
- [ ] Pass repository tests, cross-platform Rust tests, Clippy, security,
  dependency, workflow-policy, and relevant integration/conformance gates.
- [ ] Remove obsolete Python dependencies, imports, adapters, Docker contexts,
  integration tests, and workspace mounts immediately after their replacement
  passes its gates.
- [ ] Run a final consumer and release-artifact scan proving no supported path
  requires the Python MMF wheel.

### 3. Make retirement explicit

- [ ] Update READMEs, repository descriptions, catalog entries, and workspace
  metadata to name the replacement Rust crates and supported entry points.
- [ ] Add unambiguous deprecation notices to retired Python repositories.
- [ ] Disable unnecessary automation on retired repositories.
- [ ] Archive retired repositories only after consumer proof, artifact proof,
  parity gates, and maintainer review pass. Prefer archival to source deletion.

### 4. Reconcile local storage and evidence

- [x] Verify all 41 recovery bundles again and record checksums and restore
  instructions.
- [x] Copy the recovery bundles to a second access-controlled location and
  verify every size, SHA-256, bundle, restore instruction, and ACL.
- [x] Define a retention period of at least one release cycle before pruning
  rollback bundles or release evidence.
- [x] Compare metadata-free worktree shells with authoritative commits,
  manifests, and bundles before deleting any shell; preserve unique work first.
- [x] Remove the classified reproducible `.target`, virtual-environment,
  dependency, runtime-state, and test-cache tranche
  output after confirming it is not the only copy of acceptance evidence.
- [x] Keep one canonical reference clone for each required origin and commit;
  remove exact duplicates only after origin, commit, and cleanliness checks.
- [x] Treat bundles and archived snapshots as internal artifacts when they
  contain test keys, fixtures, historical configuration, or other sensitive
  material.

### 5. Reconcile hosted and beta-only resources

- [x] Inventory GitHub Actions caches, expired artifacts, packages, and OCI
  images across the migrated repositories.
- [x] Retain the last known-good beta rollback digest, SBOMs, attestations,
  acceptance evidence, and required release artifacts before pruning.
- [ ] After acceptance is closed, remove orphaned beta-only containers,
  volumes, configuration, and secrets.
- [ ] Verify explicitly that no cleanup action targets production resources.

### 6. Improve workspace hygiene

- [ ] Move active Git worktrees outside synchronized storage or exclude `.git`
  and reproducible `target`, `node_modules`, and `.venv` directories from file
  synchronization.
- [ ] Run repository-local Git maintenance only after backups are verified and
  each repository is clean.
- [ ] Re-audit local branches, worktrees, stashes, remote branches, and open
  pull requests after all cleanup changes merge.

## Change and deletion gates

Every code or repository retirement change must satisfy all applicable gates:

1. Record the old behavior in a language-neutral contract.
2. Demonstrate an owning Rust implementation without duplicated business or
   policy logic.
3. Pass positive, negative, malformed-input, authorization, and failure-mode
   parity tests appropriate to the capability.
4. Prove all intended consumers use the replacement artifact.
5. Preserve rollback evidence and verify it can be restored.
6. Land the change from a clean worktree through a focused branch, reviewed
   pull request, required CI, merge queue, and post-merge verification.
7. Delete obsolete code or archive the retired repository only after the prior
   gates pass.

Bulk local deletion additionally requires an exact resolved-path inventory,
confirmation that targets are inside the intended cleanup directory, and a
check for unique or dirty content. Production is out of scope throughout.

## Completion criteria

This cleanup is complete when:

- no supported artifact, deployment, workspace, or test depends on Python MMF;
- every retained MMF reference is clearly labeled historical or compatibility
  evidence;
- supported behavior is owned by tested, shared Rust crates;
- retired repositories and product metadata accurately reflect their status;
- local and hosted disposable artifacts have been reconciled under documented
  retention rules;
- beta-only leftovers are removed while rollback evidence is retained;
- all cleanup pull requests are merged and protections are intact; and
- a final audit reports clean local repositories, no unintended branches or
  worktrees, no open cleanup pull requests, and no production changes.
