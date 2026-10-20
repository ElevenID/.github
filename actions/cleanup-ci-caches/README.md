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

Each run defaults to at most 200 entries, one at a time with a one-second pause.
Use `max-deletions: '300'` for Core and `max-deletions: '2000'` for the other
current Marty callers to retain their existing batch limits. Values must be
integers from 1 to 2000. All shared-action callers pace deletions serially.

Successful API responses supply the remaining primary request budget. When
that budget reaches 50, the action stops making API requests and explicitly
warns/reports deferral, reserving capacity for CI. Thus a configured limit is
an upper bound, not a promise to empty the backlog in one run. Remaining
eligible caches are left for subsequent scheduled/manual runs. Unknown budget
headers do not suppress API errors; authorization failures, actual exhausted
rate-limit retries, and other API failures still fail the job.
Requests retry at most twice. Rate limits respect numeric `retry-after` seconds and primary
reset headers with at least a minute of exponential backoff. Transient HTTP
500/502/503/504 failures (including Octokit transport resets reported as 500)
use one- then two-second backoff and respect numeric `retry-after` seconds. These retries are
safe for the action's GET and delete-by-ID operations; an ambiguous deletion
followed by 404 counts as already absent. Delays over five minutes, exhausted
retries, authorization failures and other API failures fail the job. The
summary records completed deletions even on partial failure.

Run deterministic selection and failure tests with:

```sh
node --test actions/cleanup-ci-caches/cleanup.test.cjs
```

Tests use an injected clock/API and never delete live caches. A successful
caller maintenance run is the hosted integration check.
