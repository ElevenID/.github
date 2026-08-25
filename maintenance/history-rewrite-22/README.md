# Repository history rewrite review contract

Tracking issue: [#22](https://github.com/ElevenID/.github/issues/22)

This directory records the exact destructive filters and invariants for the approved historical payload cleanup. Merging this review contract does **not** rewrite a repository. The rewrite remains a separately controlled maintenance-window operation.

## Exact filters

- `marty-ui-paths.txt` is applied to `ElevenID/marty-ui` with pinned `git-filter-repo==2.47.0 --invert-paths --paths-from-file`.
- `marty-microservices-framework-paths.txt` is applied to `ElevenID/marty-microservices-framework` with the same pinned command.
- Paths are repository-relative and match across all branches and tags.
- `wheels/` is intentionally retained because the current UI policy commits three pre-built wheels.

All filtered UI paths are generated/ignored and absent from current `main`. The MMF binary is absent from current `main`.

## Reproduced preflight

| Repository | Baseline pack | Filtered pack | Reduction |
| --- | ---: | ---: | ---: |
| `marty-ui` | 100.56 MiB | 34.02 MiB | 66.2% |
| `marty-microservices-framework` | 33.66 MiB | 7.94 MiB | 76.4% |

Two independent filter runs passed strict `git fsck`, removed every targeted path from reachable history, preserved ref names, and left each current `main` tree unchanged. Full bundles passed `git bundle verify`; restoration clones matched all original refs and `main` trees.

## Mandatory final-window invariants

1. Freeze merges and pushes, drain merge queues, and freshly mirror-clone both authoritative remotes.
2. Create new complete bundles and SHA-256 checksums; restoration-test them before filtering.
3. Re-run only the checked-in filters and regenerate complete old-to-new commit/ref maps.
4. Require strict `git fsck`, zero target-path history hits, identical current `main` trees, exact candidate ref-name inventories, expected release/tag inventories, and fresh-clone measurements.
5. Publish the complete maps in this unaffected repository. Update the reviewed literal checkout pin introduced by `marty-integration-tests#339` before making rewritten history available to automation.
6. Snapshot protections/rulesets. Temporarily allow only the designated administrator's non-fast-forward update; never remove required status checks.
7. For the UI retirement, delete the backed-up releases and tags permanently, then publish only rewritten `main`; do not recreate the retired tag names and never push GitHub pull refs. Immediately restore and compare all protections/rulesets.
8. Verify remote refs, releases/assets, workflows, merge queues, historical manifest translation, fresh clones, and full required CI.
9. Instruct contributors to reclone; never allow an old clone or PR branch to restore pre-rewrite commits.
10. Roll back from the freshly tested bundles through the same controlled window if any invariant fails.

## Reviewer decision

Approval means the reviewer independently confirms that:

- every listed path is obsolete generated/tool payload rather than required source or release content;
- the exclusions are narrow enough to retain intentional assets, including `wheels/`;
- the measured benefit justifies invalidating historical commit and annotated-tag object IDs;
- the SHA translation, protection restoration, verification, contributor, and rollback controls above are adequate.

After an independent approval, the owner-recorded `GO` authorizes the maintenance-window rewrite subject to every invariant above.

## Final frozen artifacts

The refreshed owner-authorized UI retirement window froze `main` at `45f5739e99fe383444ea16b1d9d1a61642729823`; the validated rewrite maps it to `0f1cd4911a8d7a8bfe0642d131fc7b84d53aacac`. Both commits have tree `2749631b72be8cef2ef72a2ba2718d7e1a0627a9`. The earlier MMF window froze `main` at `46773c48814f3eb263b207ef5ee64bcd0deebc48`.

- UI rollback bundle SHA-256: `B23B8FC090E0C18FF4D0FC97CC8A908F89BD5D67470B9CD0CD9009337E02E9BE`
- MMF rollback bundle SHA-256: `A8DE9E22446A3B000C3A00492A1FF3B11C4DBD36DDA2D19E27FCFBE67FA8C6FE`
- UI commit map SHA-256: `B015CA9CC0D6F85572929D51F23BD315F27E5296000AC580C427E8D140158DDA`
- UI ref map SHA-256: `71FA447FA2ABE9B6D441A0414E6DAB71BAC5C5273961413DFDF48E237CFC259D`
- MMF commit map SHA-256: `8F27961FC51CD75FDCE05ED6169BEB93FC1CAA3B218773B0B438EC6DB5207208`
- MMF ref map SHA-256: `4CE3A8ADC45E7131845242E5FC99689D6F7DE3058D472F15770DDAAC1EBFD3B8`

The files under `maps/` are the unmodified `git-filter-repo` outputs from the final frozen candidates. A zero new object ID means the corresponding payload-only commit was pruned because it became empty.

Before retirement, the UI inventory contained 178 releases, 201 tags, and 1,605 release assets totaling 1,097,294,475 bytes. Every asset was downloaded and verified under a deterministic path/size/content manifest with SHA-256 `8159945978D1F7C826631CDBD095C6995D73E2C0446FA119B3891B93F952CE96`. The complete release metadata export has SHA-256 `5ECB7F8D0FEB6B4BD66FA3A979BA6EA143576BD8443C3007C483F40DB2CDEB81`; the tag-ref export has SHA-256 `C33CE7E22E18DEE0D29CD7E2BAFE4B001C4749F1801220D7A17557A9DD27FFEB`.

## Production outcome

The MMF rewrite was published on 2026-08-13. All three branches and `v1.0.0` exactly match the validated candidate, `main` moved from `46773c48814f3eb263b207ef5ee64bcd0deebc48` to `df9dbf58e1bd2be9e770109c24d67e9fa318fb0b`, and its tree remained `25dc2415c876a69f52e6781e81da05f7ce2bc15f`. A fresh standard GitHub clone is 7.60 MiB and has zero reachable hits for the removed Istio binary. GitHub-owned pull refs can retain old objects and are outside repository-owner ref control.

The UI candidate was not published in the 2026-08-13 window because immutable releases prevented lossless tag-name reuse. On 2026-08-24, the owner explicitly authorized permanent retirement of the old releases and tags in exchange for clean history. The compatibility maps merged before publication, all 178 releases and 201 tags were retired without deletion failures, and only rewritten `main` was published. `main` moved from `45f5739e99fe383444ea16b1d9d1a61642729823` to `0f1cd4911a8d7a8bfe0642d131fc7b84d53aacac` while retaining tree `2749631b72be8cef2ef72a2ba2718d7e1a0627a9`. The retired tag names are intentionally not reusable.

A fresh standard GitHub clone has one branch, zero tags, zero removed-path object hits, a 36.22 MiB pack, and passes strict `git fsck`. The historical-pin resolver translates the frozen old `main` to the published replacement and its complete ten-test unit suite passes. Post-publication [CodeQL run 32803015981](https://github.com/ElevenID/marty-ui/actions/runs/32803015981) passed against the rewritten commit; the current tree is identical to the fully gated frozen tree.

After publication, both permanent rulesets, all four required checks, one-review approval, last-pusher approval, linear history, conversation resolution, administrator enforcement, force-push prohibition, auto-merge, and UI release immutability were restored to their frozen values. The repository has no open pull requests, no releases, and no owner-visible branch other than `main`.
