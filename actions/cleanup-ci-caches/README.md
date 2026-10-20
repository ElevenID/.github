# Closed pull-request cache cleanup

Use this action at a full commit SHA in the existing cache-cleanup job. It needs
`actions: write` and `pull-requests: read`; no checkout or additional token is
needed. Keep caller concurrency serialized with `cancel-in-progress: false`.
Supported events are `pull_request` with type `closed`, `schedule`, and
`workflow_dispatch`.

Closed events select only that PR's merge-ref caches by default. Set
`include-queue-on-close: 'true'` for callers such as UI that already clean the
closed PR's queue refs immediately; this requires scanning repository caches.
Other callers retain their inexpensive exact-ref lookup. Scheduled/manual runs
also select closed PRs' merge-queue caches. Main, unrelated refs, open PRs and
reopened PRs are preserved. Selection is paginated before deletion; each PR's
current state is checked once per run. Already-missing caches are harmless.

Each run deletes at most 200 entries, one at a time with a one-second pause.
This replaces the callers' old 300/2,000-entry caps to reserve API capacity for
CI. Core and UI already pace deletes; four other callers use parallel batches.
Remaining eligible caches are left for subsequent scheduled/manual runs.
Rate-limited requests retry at most twice, respecting `retry-after` and primary
reset headers with at least a minute of exponential backoff. Delays over five
minutes, exhausted retries, authorization failures and other API failures fail
the job. The summary records completed deletions even on partial failure.

Run deterministic selection and failure tests with:

```sh
node --test actions/cleanup-ci-caches/cleanup.test.cjs
```

Tests use an injected clock/API and never delete live caches. A successful
caller maintenance run is the hosted integration check.
