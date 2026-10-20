'use strict';

const {setTimeout: sleep} = require('node:timers/promises');

module.exports = async function cleanup({github, context, core,
  maxDeletions = 200, includeQueueOnClose = false, wait = sleep, now = Date.now}) {
  const {owner, repo} = context.repo;
  if (!Number.isInteger(maxDeletions) || maxDeletions < 1 || maxDeletions > 2000) {
    throw new Error('max-deletions must be an integer from 1 to 2000.');
  }
  let remainingBudget = Infinity;
  const budgetDeferred = new Error('Cache cleanup reserved the remaining GitHub API budget.');
  const closedNumber = context.eventName === 'pull_request'
    ? context.payload.pull_request.number : null;
  if (closedNumber !== null && context.payload.action !== 'closed') {
    throw new Error('Pull-request cache cleanup requires a closed event.');
  }
  if (!['pull_request', 'schedule', 'workflow_dispatch'].includes(context.eventName)) {
    throw new Error('Unsupported cache-cleanup event.');
  }

  // Do not let an API-wide throttle turn into a parallel retry storm.
  const request = async operation => {
    for (let attempt = 0; ; attempt += 1) {
      if (remainingBudget <= 50) throw budgetDeferred;
      try {
        const response = await operation();
        const header = response?.headers?.['x-ratelimit-remaining'];
        const remaining = header === undefined ? NaN : Number(header);
        if (Number.isFinite(remaining) && remaining >= 0) remainingBudget = remaining;
        return response;
      } catch (error) {
        const headers = error.response?.headers || {};
        const limited = error.status === 429 || (error.status === 403 && (
          headers['x-ratelimit-remaining'] === '0' || headers['retry-after'] !== undefined ||
          /secondary rate limit/i.test(error.message)));
        // Octokit also reports transport resets as status 500 without a response.
        // All operations here are idempotent GET or delete-by-ID requests.
        const transient = [500, 502, 503, 504].includes(error.status);
        if ((!limited && !transient) || attempt === 2) throw error;
        const retryAfter = Number(headers['retry-after']) * 1000;
        const reset = headers['x-ratelimit-remaining'] === '0'
          ? Number(headers['x-ratelimit-reset']) * 1000 - now() : 0;
        const delay = Math.max((limited ? 60000 : 1000) * 2 ** attempt,
          Number.isFinite(retryAfter) ? retryAfter : 0,
          Number.isFinite(reset) ? reset : 0);
        // Long server-directed waits belong to a later scheduled run.
        if (delay > 300000) throw error;
        const reason = limited ? 'rate limit' : 'transient request failure';
        core.warning(`GitHub ${reason}; retrying after ${Math.ceil(delay / 1000)} seconds.`);
        await wait(delay);
      }
    }
  };

  const states = new Map();
  const seen = new Set();
  const selected = [];
  let removed = 0;
  let alreadyRemoved = 0;
  let deferred = false;
  try {
    // Finish selection before deletion so pagination cannot skip shifted entries.
    pages: for (let page = 1; ; page += 1) {
      const {data} = await request(() => github.rest.actions.getActionsCacheList({
        owner, repo, per_page: 100, page,
        ...(closedNumber === null || includeQueueOnClose
          ? {} : {ref: `refs/pull/${closedNumber}/merge`}),
      }));
      const caches = data.actions_caches || [];
      for (const cache of caches) {
        if (!cache || seen.has(cache.id)) continue;
        seen.add(cache.id);
        const match = cache.ref?.match(/^refs\/pull\/(\d+)\/merge$/)
          || cache.ref?.match(/^refs\/heads\/gh-readonly-queue\/.+\/pr-(\d+)-/);
        if (!match) continue;
        const number = Number(match[1]);
        if (closedNumber !== null && number !== closedNumber) continue;
        if (!states.has(number)) {
          const {data: pull} = await request(() => github.rest.pulls.get({owner, repo, pull_number: number}));
          states.set(number, pull.state);
        }
        // A PR can have reopened since the closed event was emitted.
        if (states.get(number) !== 'closed') continue;
        selected.push(cache);
        if (selected.length === maxDeletions) break pages;
      }
      if (caches.length < 100) break;
    }
    for (const cache of selected) {
      await wait(1000);
      try {
        await request(() => github.rest.actions.deleteActionsCacheById({owner, repo, cache_id: cache.id}));
        removed += 1;
      } catch (error) {
        if (error.status !== 404) throw error;
        alreadyRemoved += 1;
      }
      core.info(`Processed ${removed + alreadyRemoved} of ${selected.length} selected cache entries.`);
    }
  } catch (error) {
    if (error !== budgetDeferred) throw error;
    deferred = true;
    core.warning('Cache cleanup stopped before exhausting the GitHub API budget; eligible caches remain for a subsequent run.');
  } finally {
    await core.summary.addHeading('CI cache cleanup')
      .addRaw(`Removed ${removed} cache entries for closed pull requests; ${alreadyRemoved} were already absent (limit ${maxDeletions} per run).`)
      .addRaw(deferred ? ' Further API work was deferred to a subsequent run to preserve the remaining request budget.' : '')
      .write();
  }
};
