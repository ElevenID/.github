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
| `marty-ui` | 101.69 MiB | 34.34 MiB | 66.2% |
| `marty-microservices-framework` | 33.66 MiB | 7.94 MiB | 76.4% |

Two independent filter runs passed strict `git fsck`, removed every targeted path from reachable history, preserved ref names, and left each current `main` tree unchanged. Full bundles passed `git bundle verify`; restoration clones matched all original refs and `main` trees.

## Mandatory final-window invariants

1. Freeze merges and pushes, drain merge queues, and freshly mirror-clone both authoritative remotes.
2. Create new complete bundles and SHA-256 checksums; restoration-test them before filtering.
3. Re-run only the checked-in filters and regenerate complete old-to-new commit/tag maps.
4. Require strict `git fsck`, zero target-path history hits, identical current `main` trees, exact ref-name inventories, expected release/tag inventories, and fresh-clone measurements.
5. Publish the complete maps in this unaffected repository. Update the reviewed literal checkout pin introduced by `marty-integration-tests#339` before making rewritten history available to automation.
6. Snapshot protections/rulesets. Temporarily allow only the designated administrator's non-fast-forward update; never remove required status checks.
7. Push only branches and tags, never GitHub pull refs. Immediately restore and compare all protections/rulesets.
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

The owner-authorized maintenance window froze UI `main` at `e8599a2658b48e43880859e9aebdefb1d169eae5` and MMF `main` at `46773c48814f3eb263b207ef5ee64bcd0deebc48`.

- UI rollback bundle SHA-256: `7B0173798FE6A985BF839B5E7321EF6EC813B4FC0F2E4CA8B76ECE289F756991`
- MMF rollback bundle SHA-256: `A8DE9E22446A3B000C3A00492A1FF3B11C4DBD36DDA2D19E27FCFBE67FA8C6FE`
- UI commit map SHA-256: `2CC3F065B31C01B0353008E90978D6EDE4677C6006A16C6ABCD95CC2A6016083`
- UI ref map SHA-256: `A2B3623149D581702CA9E0901E54C0519B80744549B365E4B735F4E65BA68DC0`
- MMF commit map SHA-256: `8F27961FC51CD75FDCE05ED6169BEB93FC1CAA3B218773B0B438EC6DB5207208`
- MMF ref map SHA-256: `4CE3A8ADC45E7131845242E5FC99689D6F7DE3058D472F15770DDAAC1EBFD3B8`

The files under `maps/` are the unmodified `git-filter-repo` outputs from the final frozen candidates. A zero new object ID means the corresponding payload-only commit was pruned because it became empty.
