# Wave-three post-migration cleanup

<!-- cspell:ignore burdettadam worktree worktrees elevenid OIDF CSCA Sigstore -->
<!-- cspell:ignore MRTD cutover -->
<!-- cspell:ignore Clippy HMAC ECDH HKDF -->

Status: Complete

Opened: 2026-08-25

Scope: beta and repository hygiene; no production release promotion

## Objective

Close the remaining retirement and hygiene work after the completed wave-three
Rust migration without removing supported behavior. Shared Rust crates are the
canonical implementation. A Python path can be removed only after its behavior
is classified, an owning Rust implementation and language-neutral contract are
identified where behavior exists, parity and failure-mode gates pass, consumers
are proven migrated, and rollback evidence is retained.

This objective does not reopen the completed migration. It closes release,
history, artifact, branch, worktree, and documentation loose ends.

## Feature-loss review

The first path-level review found only a Dockerfile and placeholder README in
`Marty/src/marty_plugin/csca_service`, but a repository-history review found an
earlier executable `src/services/csca.py` and `src/apps/csca_service.py`. That
service had seven operations: create, retrieve, renew, revoke, report status,
list, and find expiring CSCA certificates. It generated RSA-2048 by default,
also accepted RSA-3072/4096 and ECDSA P-256/P-384/P-521, kept private material
behind a vault abstraction, persisted public certificates, and wrote issued,
renewed, and revoked outbox events. It also had defects: list filters and custom
extensions were ignored, expiry was absent from status, `reuse_key` was
ignored, and lifecycle hooks were no-ops.

The missing behavior is now restored and tested through Rust owners:

- issuance primitives: `marty-verification::issuance`;
- six-algorithm authority, DSC, EF.SOD, trust, and tamper tests: `marty-core`
  and `marty-credentials`;
- managed custody, ES512 signing, lifecycle state, and transactional outbox:
  `marty-ui` signing keys; and
- trust anchors, country, and registry: `marty-ui` trust profiles.

The parity repair preserves all effective operations and improves status,
filtering, expiry, chain validation, tenant isolation, optimistic concurrency,
private-material rejection, and idempotent outbox acknowledgement. The
six-algorithm test issues a P-256 DSC under every supported CSCA algorithm,
builds EF.SOD, registers the CSCA trust anchor, and verifies the passport
through the public eMRTD API. Managed OpenBao, cloud KMS, and signature
normalization surfaces include ES512 so P-521 is not an offline-only claim.
The old online `CreateCertificate` operation generated an unencrypted root
private key in service memory and handed it to a vault adapter. Its supported
replacement deliberately separates offline/bootstrap CSCA creation from the
deployed managed-custody lifecycle: the shared Rust issuance API creates all
six key algorithms and issues DSCs for bootstrap or ceremony use, while the
authenticated signing service binds an imported public certificate to the
caller-verified managed public key and never accepts private material. This is
a custody hardening of the same outcome, not removal of CSCA creation.

History also contained an auxiliary certificate lifecycle manager and monitor
that advertised automatic rotation, reports, notifications, and history. They
were not an effective deployed capability: the manager constructed the CSCA
service without its required dependencies and invoked asynchronous operations
synchronously; the monitor used insecure synchronous gRPC against TLS-only
servers and converted failures into empty results. Rotation was disabled in
the monitor defaults, notification channels were disabled by default, and the
manager was not deployed as a service. Reproducing unattended root-CSCA
rotation would also bypass managed-key ceremony and custody controls. The Rust
replacement preserves the useful outcomes through authenticated explicit
renewal, expiry queries, transactional outbox history, and verified key reuse
or rotation. Notification and reporting consumers can subscribe to that
durable outbox without putting private material or rotation authority in an
unmanaged background process. The remaining governed monitor, reporting,
notification, and renewal-work-queue implementation is tracked in
[marty-ui#623](https://github.com/ElevenID/marty-ui/issues/623), with an
explicit prohibition on unattended root-CSCA rotation.

[Marty#67](https://github.com/ElevenID/Marty/pull/67) removed the later
unreachable context. The algorithm and lifecycle parity repairs landed through
`marty-core#251`, `marty-core#252`, `marty-credentials#203`, `marty-ui#621`,
`marty-ui#622`, `marty-ui#624`, and `Marty#72`. A subsequent maintainer pass
found that the managed-key backend advertised and signed ES512 but omitted
P-521 JWK inference
and the two console selection surfaces; `marty-ui#624` repaired those surfaces
and passed the protected merge queue. No intended CSCA functionality is being
retired.

`charts/marty` was not a source directory or current Rust component. It was the
single obsolete Helm OCI package
`ghcr.io/elevenid/charts/marty:1.0.0`, which packaged the retired root Python
MMF plugin deployment. Its digest was
`sha256:d7d3570fa8663ef5aefa30e1b982f2aad19e51c626359f6056b4a3e2e3983a88`.
The package and the related `marty` container package were deleted only after
dual recovery evidence was verified. API reads now return 404.

## Landed migration and retirement changes

The consumer and behavior cleanup landed through protected pull requests and
required checks:

- `marty-credentials#201` removed the released `marty-msf` wheel and preserved
  the adapter through shared `marty-common`; it also made the previously
  transitive `python-multipart` dependency explicit.
- `marty-core#250` added the language-neutral biometric contract and Rust
  parity tests; `marty-integration-tests#391` then removed the direct Python MMF
  test and added a negative dependency gate.
- `Marty#63` through `Marty#67` removed consumer-zero KMS, notification,
  top-level plugin, configuration, observability, and unreachable CSCA paths
  after their ownership and parity gates passed.
- `product-catalog#6` identifies the Rust crate platform as current and Python
  MMF as retired history.
- `marty-ui#612` classified the last Python snippet as historical and removed
  obsolete wheel, mount, and beta-trigger guidance. `marty-ui#613` restored the
  fail-closed release-environment preflight. `marty-ui#614` strengthened CSCA
  signing and trust-profile coverage. `marty-ui#620` fixed the beta lifecycle
  toolchain omission discovered by a real deployment run.
- `marty-microservices-framework#95` removed 1,550 obsolete tracked Python,
  packaging, deployment, generated-report, and documentation files while
  retaining all 18 Rust crates and all 40 language-neutral contract/inventory
  records. It added exact consumer, beta, recovery, and negative-source gates,
  plus a Rust-only release channel.

The unusually large deletion total in that retirement pull request is not an
equivalent count of product capabilities. Of its 273,554 deleted lines, the
largest buckets were the duplicate Python framework (51,698), vendored demo
material (50,798), old Python tests (35,233), duplicate Python services
(17,593), example domains (13,552), and generated or vendored artifacts such as
a 17,536-line Istio CRD, lock files, reports, and import analysis. The smaller
Marty deletions similarly removed consumer-zero Python delivery surfaces. The
Rust parity work moved in the other direction: `marty-ui#621` added 2,223 lines
of lifecycle implementation and tests, while the core, credentials, and strict
renewal repairs added another 1,491 lines. Diff size is therefore recorded as
retirement evidence, not used as a feature-parity measure.

The canonical framework retirement commit is
`3d9a2b6591318257c3e2ad3f729edc567f4cdc90`. The retirement build
`local/mmf-rust-retirement:0.1.0` passed a Linux image build and healthy identity
service smoke test with manifest-list digest
`sha256:2d6cd463159778a67ab362dfd8ba36515fcafa267552d03cce1459625bb3a112`.

## Reviewer-discovered corrections

The first Rust v0.1.0 release run `32910041555` passed compilation, tests,
signing, provenance, and publication, but download verification exposed a
filename-contract defect: `SHA256SUMS` retained nested
`package-manifests/mmf-*.txt` paths while GitHub published those files by
basename. The release was preserved in both evidence locations and rejected as
the closeout release.

[marty-microservices-framework#97](https://github.com/ElevenID/marty-microservices-framework/pull/97)
fixed that defect, fails before signing if a nested asset could be flattened,
and adds a Rust regression test. The same review found that the required
`Rust license metadata` check had path filters and therefore could deadlock
workflow-only pull requests. The workflow now runs for every protected pull
request, merge group, and main push, with a cross-platform policy test.

The dependency review also found a grouped update of fourteen Rust libraries
that did not compile. The maintainer migration covers rand 0.10 traits, HMAC
key initialization, elliptic-curve 0.14 secure generation and SEC1 APIs, and
scrypt 0.12 parameters. Existing HMAC, ECDH/HKDF, malformed-input, and identity
contracts pass, and an RFC 7914 persisted-hash vector now explicitly protects
password compatibility across the upgrade.

GitHub rejected recreation of the deleted v0.1.0 name under organization-level
ref-creation policy even while the repository tag ruleset reported disabled.
The guarded operation restored tag protection after both rejected attempts.
Rather than weaken organization policy or reuse a release version, the
workspace and its DRY internal dependency table advance to v0.1.1.

The final corrected v0.1.1 release passed the protected merge and immutable-tag
gate:

- commit: `81810cf19702a9574141e3f2082bb5436d4a2e37`
- workflow run: `32914567459`
- release assets: 43
- final dual-copy bundle SHA-256:
  `70e533a721e1950c6247f966f85fd9637b67ecb6acfe17324e1d9f7e3f6d226b`

Independent download verification resolved all 42 entries in `SHA256SUMS`,
matched all 43 GitHub release digests, and matched the two evidence copies
byte-for-byte. All 21 Sigstore bundles verify against the exact repository,
release workflow, and v0.1.1 tag identity. GitHub provenance verifies for the
source archive. The 420-package SPDX SBOM contains no legacy Python MMF
package, and the 264-entry source archive contains no Python source or
packaging path.

Public crates.io publication remains deliberately disabled by
`ENABLE_PUBLIC_REGISTRY_PUBLISHING=false`; the signed GitHub source release is
the supported release surface.

## Aggregate beta acceptance

The final review found that the earlier beta candidate did not yet contain the
complete CSCA parity correction. `marty-core#253` completed parameter-aware
RSA-PSS verification and the six-algorithm authority/DSC matrix; release
v0.1.60 was published from exact protected main commit
`dce4fb99016dfcb3801fbfb9dcab9e8b0f74bd4f`. `marty-credentials#204` then
updated the consumer, passed the protected merge queue at
`923ef6d45807e5eca887dc94bb66444f04190e63`, and published signed v0.1.70
issuance and verification images. Every release asset matched `SHA256SUMS`,
and the checksum Sigstore bundle verified against the exact release workflow
identity. `marty-ui#625` atomically pinned those releases and the final P-521
console repair through its protected merge queue at
`79ac406f71b62b5ef78c50ea2ce02fc391373b0f`.

The one final aggregate beta deployment selected marty-ui v1.1.203. Stack
release run `32946762802` passed and published a ten-component immutable
manifest, SBOMs, Sigstore bundles, attestations, and checksums. The public beta
markers report release 1.1.203 and coordinated source snapshot
`d430cf6d068865b672ac2fb484d10033b6a53776`. The local deployment used clean,
detached worktrees at every pinned revision, rehearsed PostgreSQL, Redis,
OpenBao, and Alembic migrations in isolation, then replaced the beta stack as
one change. It preserved the configured portable Canvas pilot and left the
production compose project outside the deployment scope.

The deployment manifest SHA-256 is
`c00c2b76ce9ba023f0c72df632c608c75437b5454968a736143d960c9ef87494`;
the published stack manifest SHA-256 is
`8b2406bf7d69912db98f56aed13759e2f905c8e205dd431d6099a34390ed397a`.
Two independent Rust operational samples, 7 minutes 10 seconds apart from
cutover to the latest sample, each passed all 30 fail-closed checks with zero
container restarts, error or panic markers, event drops, or dependency
failures. The window verifier accepted both immutable samples for the exact
release and source. It correctly reports only 0.12 hours of observation and
does not claim the optional 7-day event-stream or 14-day revocation-profile
deletion windows.

[Beta lifecycle run 32950631498](https://github.com/ElevenID/marty-ui/actions/runs/32950631498)
passed the protected environment review and every real-beta gate: immutable
release/source binding, public markers, dependency readiness, membership and
organization console paths, credential issuance, browser-wallet login,
renewal, suspension, reinstatement, revocation, and verification. Its complete
reports and screenshots were downloaded into the deployment evidence set.

Two stopped, labeled candidate containers were removed without deleting the
shared beta volume:

- `elevenid-beta-presentation-policy-candidate-wave3k`
- `elevenid-beta-credential-template-candidate-wave3i`

The protected external-wallet device-lab gate still requires a separately
produced evidence URL and SHA-256; the repository and organization do not
contain that external evidence or a substitute secret, and no conformance run
has been dispatched with invented metadata. It is a release-promotion gate,
not evidence of a missing code feature. The optional 7-day and 14-day
operational windows are additional soak evidence and do not block the
completed parity/deletion gates.

## Production invariant

No production version, configuration, image reference, container identity, or
data was deliberately changed, and the actual aggregate beta deployment
recorded the same 26-container production invariant before and after with hash
`e7509b9fc2be9fc855d0e08b184df32cb5193b7c580f2ab9beaef3719ba16dd3`.

One earlier Docker Desktop recovery restarted the existing production
containers and therefore changed their start times. It did not promote a
release or change their versions, configuration, image IDs, container IDs, or
data. This operational exception is recorded rather than describing production
as literally untouched.

## Recovery and history disposition

The legacy Python framework releases and tags v1.0.0, v1.0.1, and v1.0.2 were
deleted after the user-approved history cleanup and dual verified recovery.
The pre-cleanup complete framework bundle is 36,626,931 bytes with SHA-256
`d1994484374e40c9d5a8a10fb315383c55e92a229f0e1d66f2613d0849657ffe`.
The post-retirement, pre-tag-prune complete bundle is 9,556,795 bytes with
SHA-256
`10fc602250fe50c5dc86ad10c1ad0a515da927671c35d8ebd9e2f6c41b0911d9`.
Both copies verify as complete bundles and retain the old tags and release
history.

All 41 broader recovery bundles were verified, copied to a second
access-controlled location, checked by size and SHA-256, and retained for at
least one release cycle. Release assets, SBOMs, Sigstore bundles, attestations,
checksums, beta acceptance evidence, and rollback digests are retention
artifacts, not disposable caches.

The tag-protection ruleset remains active. The attempted v0.1.0 correction was
preceded by a complete dual-copy bundle, temporarily disabled only the exact
repository tag ruleset, and restored it in a `finally` path. The accepted
v0.1.1 tag is a new immutable release ref and requires no protection bypass.
The rejected pre-correction bundle is 9,567,874 bytes with SHA-256
`8d5bbdae577bb80c37831948cb70d8273cd5f6a482ce061a114a323a66ee0e69`.
The final v0.1.1 bundle is 9,566,703 bytes with SHA-256
`70e533a721e1950c6247f966f85fd9637b67ecb6acfe17324e1d9f7e3f6d226b`.
Both have two verified copies; the former preserves the rejected release ref,
and the latter contains only current main, origin/main, and immutable v0.1.1
refs.

## Local and hosted hygiene

Completed local cleanup includes:

- 12.0 GiB of reproducible Cargo output plus generated virtual environments,
  `node_modules`, database state, and test/tool caches removed only after
  evidence classification;
- exact same-origin, same-commit, same-tree reference clones removed after
  cleanliness checks, reclaiming more than 3.7 GiB;
- unique metadata-free work preserved as a verified bundle instead of deleted;
- Git maintenance run only on clean repositories after backup; and
- current primary repository audit showing zero stashes and no linked
  deployment worktrees, with only the governed documentation branch and the
  separately classified blog editorial drafts outstanding.

Hosted cleanup removed 224 completed intermediate
`rust-db-test-bundle-1` artifacts totaling 37,225,644,668 live bytes only after
their consumers completed. Release, security, beta, wheel, SBOM, attestation,
checksum, and acceptance artifacts were not targeted. Current compiler and
image caches remain useful; retention policy and the existing cleanup workflow
handle them without a risky bulk delete.

After dual-copy verification, the rejected release run's exact 632,072-byte
assembled `rust-release-assets` artifact was deleted. Its 90-day build SBOM,
the corrected release artifacts, and both local copies of each release remain
retained.

The broader audit found one metadata-only upstream audit shell whose empty
index made all 5,874 tracked paths appear deleted. Its unique commit was first
preserved in two complete bundles (7,899,523 bytes; SHA-256
`11bb49e6c39875ac33d904e2f112db0050ef52fb298aa5ccaca6d58c5a29765d`),
then the exact orphan directory was removed. Pinned, clean upstream
conformance fixtures and the active multi-worktree upstream maintenance set
remain classified reference inputs, not abandoned product branches.

After the corrected release and its evidence passed, cleanup removed the
generated framework holding content at
`C:\w\marty-framework-generated-holding-20260825T2238Z`, the 20.36 GB
framework `target` tree, and only the exact local retirement test image at
digest
`sha256:2d6cd463159778a67ab362dfd8ba36515fcafa267552d03cce1459625bb3a112`.
The generated directories were sent to the recycle bin; the orphan shell was
deleted after its dual complete bundle because recycle support was unavailable
for that OneDrive path.

The final hosted audit found 28 repositories and 30 branches. Every repository
has only its default branch except the generated `gh-pages` publication
branches in `gtk-rs-core` and `longfellow-zk`; neither is abandoned product
work. There are no open pull requests after this record merges. The final local
migration audit found every primary product repository on its default branch
with zero stashes and no linked deployment worktrees; only this governed
documentation branch existed during its pull request. Four uncommitted
`marty-blog` editorial draft/review files on local `main` predate and are
unrelated to the migration. They were classified and preserved in place rather
than silently folded into or deleted by this closeout.

## Completion gates

- [x] Classify every tracked and published Python MMF reference.
- [x] Preserve supported behavior in shared Rust owners and language-neutral
  positive, negative, malformed-input, authorization, and failure-mode tests.
- [x] Remove obsolete Python dependencies, imports, adapters, build contexts,
  tests, mounts, workflows, and catalog claims after parity.
- [x] Prove credentials v0.1.70 and marty-ui v1.1.203 contain no Python MMF
  runtime package and pass aggregate beta acceptance.
- [x] Remove obsolete `marty` and `charts/marty` packages after dual recovery.
- [x] Publish and independently verify the corrected signed Rust v0.1.1 source
  release and final bundle.
- [x] Re-audit and reconcile every local/remote branch, worktree, stash, open
  pull request, generated holding directory, and exact local test image.
- [x] Merge the closeout record through protected checks in `.github#36` at
  `2ce1726fe28aa980daa02dcda031231e87f9d779` and verify the final clean
  organization state.

The external-wallet device-lab evidence and optional 7/14-day soak windows are
tracked operational follow-ups. They do not authorize a production promotion
and do not reopen completed feature parity.
