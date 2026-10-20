'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const cleanup = require('./cleanup.cjs');

const cache = (id, ref = 'refs/pull/12/merge') => ({id, ref});
const error = (status, headers = {}, message = 'API failure') =>
  Object.assign(new Error(message), {status, response: {headers}});

function harness({pages = [[]], states = {}, event = 'schedule', action = 'closed', remove, list, pull} = {}) {
  const calls = {lists: [], pulls: [], deletes: [], waits: [], warnings: [], summaries: []};
  const summary = {
    addHeading() { return this; },
    addRaw(text) { calls.summaries.push(text); return this; },
    async write() {},
  };
  const args = {
    github: {rest: {
      actions: {
        async getActionsCacheList(params) {
          calls.lists.push(params);
          if (list) return list(params, calls);
          return {data: {actions_caches: pages[params.page - 1] || []}};
        },
        async deleteActionsCacheById(params) {
          calls.deletes.push(params.cache_id);
          if (remove) return remove(params, calls);
        },
      },
      pulls: {async get(params) {
        calls.pulls.push(params.pull_number);
        if (pull) return pull(params, calls);
        return {data: {state: states[params.pull_number] || 'closed'}};
      }},
    }},
    context: {repo: {owner: 'ElevenID', repo: 'fixture'}, eventName: event,
      payload: {action, pull_request: {number: 12}}},
    core: {summary, info() {}, warning(text) { calls.warnings.push(text); }},
    async wait(ms) { calls.waits.push(ms); },
    now: () => 1000000,
  };
  return {args, calls};
}

test('scheduled cleanup preserves main, open PRs and unrelated refs; deduplicates closed PR and queue caches', async () => {
  const {args, calls} = harness({pages: [[
    cache(1, 'refs/heads/main'), cache(2, 'refs/pull/10/merge'), cache(3), cache(3),
    cache(4, 'refs/heads/gh-readonly-queue/release/stable/pr-12-abc'),
    cache(5, 'refs/tags/v1'), cache(6, 'refs/pull/12/head'), null,
  ]], states: {10: 'open'}});
  await cleanup(args);
  assert.deepEqual(calls.deletes, [3, 4]);
  assert.deepEqual(calls.pulls, [10, 12]);
  assert.deepEqual(calls.waits, [1000, 1000]);
  assert.match(calls.summaries[0], /Removed 2/);
});

test('closed event is scoped to its merge ref and rechecks whether the PR reopened', async () => {
  for (const state of ['open', 'closed']) {
    const {args, calls} = harness({event: 'pull_request', states: {12: state},
      pages: [[cache(1), cache(2, 'refs/pull/13/merge')]]});
    await cleanup(args);
    assert.equal(calls.lists[0].ref, 'refs/pull/12/merge');
    assert.deepEqual(calls.pulls, [12]);
    assert.deepEqual(calls.deletes, state === 'closed' ? [1] : []);
  }
});

test('selection paginates before deletion and leaves entries beyond the run bound', async () => {
  const {args, calls} = harness({pages: [
    Array.from({length: 100}, (_, i) => cache(i)),
    Array.from({length: 100}, (_, i) => cache(i + 100)),
    [cache(200)],
  ], remove() { assert.equal(calls.lists.length, 2); }});
  await cleanup(args);
  assert.equal(calls.deletes.length, 200);
  assert.equal(calls.lists.length, 2);
  assert.equal(calls.waits.length, 200);
  assert.ok(!calls.deletes.includes(200));
});

test('manual cleanup follows pages containing only ineligible caches', async () => {
  const {args, calls} = harness({event: 'workflow_dispatch', pages: [
    Array.from({length: 100}, (_, i) => cache(i, 'refs/heads/main')), [cache(100)],
  ]});
  await cleanup(args);
  assert.equal(calls.lists.length, 2);
  assert.deepEqual(calls.deletes, [100]);
});

test('404 is harmless; other failures stop deletion and preserve a partial summary', async () => {
  const {args, calls} = harness({pages: [[cache(1), cache(2), cache(3), cache(4)]],
    remove({cache_id}) {
      if (cache_id === 2) throw error(404);
      if (cache_id === 3) throw error(500);
    }});
  await assert.rejects(cleanup(args), {status: 500});
  assert.deepEqual(calls.deletes, [1, 2, 3]);
  assert.match(calls.summaries[0], /Removed 1.*1 were already absent/);
});

test('429 retries the same deletion after retry-after, without overlapping requests', async () => {
  const {args, calls} = harness({pages: [[cache(1), cache(2)]], remove() {
    if (calls.deletes.length === 1) throw error(429, {'retry-after': '90'});
  }});
  await cleanup(args);
  assert.deepEqual(calls.deletes, [1, 1, 2]);
  assert.deepEqual(calls.waits, [1000, 90000, 1000]);
  assert.equal(calls.warnings.length, 1);
});

test('delete calls never overlap', async () => {
  let active = 0;
  let maximum = 0;
  const {args} = harness({pages: [[cache(1), cache(2), cache(3)]], async remove() {
    active += 1;
    maximum = Math.max(maximum, active);
    await new Promise(resolve => setImmediate(resolve));
    active -= 1;
  }});
  await cleanup(args);
  assert.equal(maximum, 1);
});

test('rate-limited reads retry too; primary reset is respected', async () => {
  const {args, calls} = harness({list(params, history) {
    if (history.lists.length === 1) throw error(403,
      {'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1120'});
    return {data: {actions_caches: [cache(1)]}};
  }, pull(params, history) {
    if (history.pulls.length === 1) throw error(403, {}, 'You have exceeded a secondary rate limit');
    return {data: {state: 'closed'}};
  }});
  await cleanup(args);
  assert.deepEqual(calls.waits, [120000, 60000, 1000]);
  assert.deepEqual(calls.deletes, [1]);
});

test('exhausted throttles and long reset windows fail instead of hiding incomplete cleanup', async () => {
  for (const failure of [error(429), error(403,
    {'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '2000'})]) {
    const {args, calls} = harness({pages: [[cache(1)]], remove() { throw failure; }});
    await assert.rejects(cleanup(args), failure);
    assert.equal(calls.deletes.length, failure.status === 429 ? 3 : 1);
    assert.deepEqual(calls.waits, failure.status === 429 ? [1000, 60000, 120000] : [1000]);
    assert.match(calls.summaries[0], /Removed 0/);
  }
});

test('authorization errors are never retried and unsupported events never call the API', async () => {
  const {args, calls} = harness({list() { throw error(403); }});
  await assert.rejects(cleanup(args), {status: 403});
  assert.equal(calls.lists.length, 1);
  assert.deepEqual(calls.waits, []);
  for (const options of [{event: 'push'}, {event: 'pull_request', action: 'opened'}]) {
    const h = harness(options);
    await assert.rejects(cleanup(h.args));
    assert.deepEqual(h.calls.lists, []);
  }
});
