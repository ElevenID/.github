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
still make retired Python MMF paths appear supported:

- `marty-credentials` declares the released `marty-msf` wheel and retains an
  MMF migration-adapter import.
- `Marty` declares the same wheel and retains MMF plugin, notification,
  configuration, and Docker build paths.
- `marty-integration-tests` retains MMF-specific integration coverage.
- the Hermes workspace configuration still mounts the MMF repository.
- product catalog data still describes MMF as a current offering.
- `Marty`, `marty-credentials`, and `marty-microservices-framework` are not
  archived on GitHub.

These references may be compatibility, historical, test-only, or obsolete.
They must be classified before a repository is archived or a path is deleted.

The operator-local inventory also found approximately:

- 12.0 GiB of reproducible Rust build output under `.target`;
- 60 metadata-free worktree shells totaling 5.0 GiB;
- 6.7 GiB under `work`, mixing evidence with reproducible environments; and
- several same-origin, same-commit reference clones under `C:\w`.

Recovery evidence currently includes 40 verified Git bundles totaling about
1.46 GB. Those bundles are retained evidence, not disposable cache.

## Execution backlog

### 1. Classify legacy references

- [ ] Produce a repository-and-path inventory for every remaining Python MMF
  dependency, import, build context, workspace mount, test, and product claim.
- [ ] Mark each reference as supported runtime, supported compatibility,
  test-only, historical documentation, or obsolete.
- [ ] Identify the owning Rust crate and language-neutral behavior contract for
  every supported runtime or compatibility capability.
- [ ] Confirm published artifacts and deployment manifests do not introduce
  additional consumers that source search misses.

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

- [ ] Verify the 40 recovery bundles again, copy them to a second
  access-controlled location, and record checksums and restore instructions.
- [ ] Define a retention period of at least one release cycle before pruning
  rollback bundles or release evidence.
- [ ] Compare metadata-free worktree shells with authoritative commits,
  manifests, and bundles before deleting any shell; preserve unique work first.
- [ ] Remove reproducible `.target`, virtual-environment, test-cache, and repro
  output after confirming it is not the only copy of acceptance evidence.
- [ ] Keep one canonical reference clone for each required origin and commit;
  remove exact duplicates only after origin, commit, and cleanliness checks.
- [ ] Treat bundles and archived snapshots as internal artifacts when they
  contain test keys, fixtures, historical configuration, or other sensitive
  material.

### 5. Reconcile hosted and beta-only resources

- [ ] Inventory GitHub Actions caches, expired artifacts, packages, and OCI
  images across the migrated repositories.
- [ ] Retain the last known-good beta rollback digest, SBOMs, attestations,
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
