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
- `Marty` declares the Python wheel and retains MMF plugin, notification,
  configuration, KMS-compatibility, and Docker build paths.
- `Marty` and `marty-credentials` are active mixed-language repositories and
  are not archive candidates while they own supported artifacts.

These references may be compatibility, historical, test-only, or obsolete.
They must be classified before a repository is archived or a path is deleted.

## Initial reference classification

- `marty-microservices-framework` is the active canonical Rust crate
  repository. Keep the repository and Rust releases; retire only its Python
  package after consumer proof.
- `marty-ui` is an active Rust consumer. Keep its Cargo pins, release inputs,
  and source references to the Rust `mmf-*` crates.
- `marty-subscriptions` is an active self-host build consumer. Keep the
  canonical repository input while the build consumes its Rust crates.
- the Hermes workspace is a development and audit consumer. Keep the mount
  because it exposes the active Rust crate source.
- `marty-credentials` owns supported Python service images with Rust-backed
  domain operations. Remove the Python MMF wheel while preserving required
  adapter behavior; this is tracked by `marty-credentials#201`.
- `Marty` is the remaining mixed-source Python MMF consumer. Trace released
  consumers, add parity evidence, then remove or replace each live import.
- `Marty/packages/marty-common/marty_common/crypto/credential_kms.py` is an
  active released-package compatibility surface, not root-plugin-only code. It
  imports the legacy KMS port while canonical Rust ownership exists in
  `mmf-security::KmsProvider`. Preserve the Python behavior until the Rust
  contract covers its algorithm, key-identity, expiration, HSM, rotation,
  listing, deletion, and failure semantics and the adapter has parity tests.
- `Marty/src/marty_plugin` is the root plugin entry point and directly depends
  on the legacy plugin lifecycle and configuration APIs. Its release image has
  no known deployment-manifest consumer, but consumer absence alone is not a
  parity gate; map its trust-anchor, PKD, document-signer, and CSCA surfaces
  before retiring the artifact.
- `Marty/src/notifications` retains Python MMF push-provider imports. Classify
  its challenge delivery, token lifecycle, FCM, and SSE behavior against the
  canonical `mmf-push` crate before changing it.
- `marty-integration-tests` has removed its direct Python MMF biometric test in
  pull request 391. Historical rewrite evidence remains intentionally retained.
- product catalog positioning is corrected by merged pull request 6.
- history and migration documents are evidence. Retain accurate records and
  label them historical instead of treating them as live dependencies.

Repository-name matches alone are not evidence of a Python dependency. The
consumer gate must distinguish Python package/import tokens (`marty-msf`,
`marty_msf`, and `mmf.*`) from valid Git and build references to the Rust crate
repository.

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

Current `Marty` path classification:

- `packages/marty-common/.../credential_kms.py` is supported compatibility.
  Port and parity-test it against `mmf-security`; do not delete it yet.
- `src/marty_plugin` and its entry point form a published root artifact with no
  known stack consumer. Prove Rust ownership for its four exposed services,
  then retire it.
- `src/notifications` is packaged compatibility behavior. Contract-test it
  against `mmf-push`, then remove the Python imports.
- `src/marty_plugin/trust_anchor/modern_trust_anchor.py` is a packaged legacy
  configuration and observability adapter. Replace it with shared Rust runtime,
  configuration, and observability composition.
- `src/digital_identity` contains mixed historical documentation and optional
  adapter code. Separate documentation from reachable package code and test
  each live path.
- `k8s`, Helm, Docker, and the root release workflow deliver only the root
  plugin. Remove them with that artifact after parity and consumer gates.
- `packages/marty-common`, excluding classified compatibility paths, is an
  active released shared library and must be retained.

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
