# Local implementation evidence

Keep source, behavioral contracts, synthetic fixtures, schemas, operational
runbooks, and the tools that reproduce checks in Git. Generated logs, screenshots,
test results, downloaded CI artifacts, and completed agent reuse-review records
belong in ignored local output directories or CI artifacts. Put change-specific
implementation and completion notes in the PR description, rather than adding
permanent session summaries to the source tree.

Delete local implementation evidence when its review or investigation closes.
For unattended leftovers, the workspace cleanup tool uses a 30-day TTL for ordinary disposable output in
`artifacts/` and `_codex-artifacts/`, and 14 days for diagnostic, validation, and
`test-temp/` output. Age is the newest modification anywhere in each direct child
tree, so writing fresh evidence keeps that entire child. These are local scratch
defaults, not retention rules for published releases, attestations, required
assurance records, or performance baselines.

Run from the multi-repository workspace, using Python 3.9 or newer:

```powershell
python elevenid-dot-github/scripts/prune_local_evidence.py .
python elevenid-dot-github/scripts/prune_local_evidence.py . --apply
```

The first command only previews. Review its list before running the second command,
which deletes expired output. Preservation is based on names: the tool cannot
identify required assurance records stored under generic names. Move those records
out of scratch containers before applying cleanup.
The tool only examines named workspace output containers. It preserves nested
Git repositories, filesystem mounts (including Linux bind mounts), symlinks/reparse points, and trees with any descendant whose name
identifies backups, archives, predeletion evidence, recovery, self-host installations,
runtime state, release manifests/attestations, baselines, snapshots, or rollback
records. It never cleans worktrees or build targets. Review those
separately using Git worktree status and deployment ownership. Run cleanup while
the selected old output is idle; do not run it alongside writers to those paths.

Repository `.gitignore` rules prevent new generated output being added normally;
already tracked files require explicit removal from the current tree or index.
New generated report output belongs under `reports/generated/`; source fixtures,
contracts, baselines and runbooks are not blanket-ignored. Ignore rules do not erase Git history. Historical release and history-rewrite
procedures remain separate maintenance operations.
