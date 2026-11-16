// Executes the exact owner-page script with a DOM, storage and console-post
// double. This is a client state-ordering control, not browser, passkey or
// server qualification: the saved selection must exist before the send, a
// retry must reuse it, no error may clear it, and only a final history entry
// for its operation lets the page forget it.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const scope = 's-0123abcd';
const team = 'engineering:customer.example';
const certificate = '11111111-1111-4111-8111-111111111111';
const key = `aweb.owner-removal:${scope}:${certificate}`;

let uuids = 0;

function page({finals = [], stored = {}, answers}) {
  const store = new Map(Object.entries(stored));
  const sessionStorage = {
    getItem: k => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: k => store.delete(k),
    key: i => [...store.keys()][i] ?? null,
    get length() { return store.size; },
  };
  const status = {textContent: ''};
  const row = {children: [], append(node) { this.children.push(node); }};
  const button = {dataset: {removeCertificate: certificate}, disabled: false, events: {}, focused: false,
    addEventListener(name, fn) { this.events[name] = fn; }, closest: selector => (selector === 'li' ? row : null),
    focus() { this.focused = true; }};
  const list = {dataset: {teamId: team, storageScope: scope, operation: "team.agent.remove", variant: "owner_approved"},
    querySelectorAll: selector => (selector === '[data-remove-certificate]' ? [button] : [])};
  const finalItems = finals.map(id => ({dataset: {finalOperation: id}}));
  const sent = [];
  const storedAtSend = [];
  const assigned = [];
  const context = {
    console, JSON, Error, String, encodeURIComponent,
    sessionStorage,
    crypto: {randomUUID: () => `00000000-0000-4000-8000-00000000000${++uuids}`},
    document: {
      getElementById: id => ({'owner-members': list, 'owner-remove-status': status})[id] ?? null,
      querySelectorAll: selector => (selector === '[data-final-operation]' ? finalItems : []),
    },
    window: {
      location: {assign: url => assigned.push(url)},
      awebConsole: {post: async (path, body) => {
        sent.push([path, JSON.parse(JSON.stringify(body))]);
        storedAtSend.push(sessionStorage.getItem(key));
        return answers.shift()();
      }},
    },
  };
  vm.runInNewContext(fs.readFileSync('src/aweb/protected_signing/owner.js', 'utf8'), context,
    {filename: 'owner.js'});
  return {button, status, row, sent, storedAtSend, assigned, store};
}

const refusal = detail => () => { const e = new Error('Request refused'); e.status = 409; e.detail = detail; throw e; };
const lost = () => { throw new TypeError('Failed to fetch'); };

(async () => {
  // Lost answer, then a refusal, then success: one selection throughout.
  const p = page({answers: [lost, refusal('operation_conflict'), () => ({handoff_id: 'h-1'})]});
  for (let attempt = 0; attempt < 3; attempt++) await p.button.events.click();
  const [first] = p.sent;
  assert.equal(first[0], '/governance/operations');
  assert.deepEqual(Object.keys(first[1]).sort(),
    ['certificate_id', 'operation', 'operation_id', 'team_id', 'variant']);
  assert.deepEqual({...first[1], operation_id: undefined}, {operation_id: undefined,
    operation: 'team.agent.remove', variant: 'owner_approved', team_id: team, certificate_id: certificate});
  assert.ok(p.sent.every(([, body]) => JSON.stringify(body) === JSON.stringify(first[1])),
    'a retry sent a different selection');
  assert.ok(p.storedAtSend.every(saved => JSON.parse(saved).operation_id === first[1].operation_id),
    'the selection was not saved before it was sent');
  assert.deepEqual(p.assigned, ['/handoff/h-1']);
  // Success does not prove a final receipt either: the selection stays.
  assert.equal(JSON.parse(p.store.get(key)).operation_id, first[1].operation_id);

  // A refusal the signer names says only why; it never invites a retry that
  // would get the same answer. The selection is still kept.
  const named = {
    subject_ineligible: 'This member cannot be removed here.',
    authority_changed: "The team's approval settings changed. Reload the page.",
    scope_refused: 'Another approver or team started this request.',
  };
  for (const [code, sentence] of Object.entries(named)) {
    const q = page({answers: [refusal(code)]});
    await q.button.events.click();
    assert.equal(q.button.disabled, false);
    assert.equal(q.status.textContent, sentence);
    assert.ok(q.store.has(key));
  }
  // No answer at all: not confirmed, and a retry sends the same request.
  const unconfirmed = 'The request was not confirmed. Nothing is removed until you approve it on its page. ' +
    'Trying again sends the same request.';
  const none = page({answers: [refusal('receipt_unavailable')]});
  await none.button.events.click();
  assert.equal(none.status.textContent, 'No answer came back. ' + unconfirmed);
  const dropped = page({answers: [lost]});
  await dropped.button.events.click();
  assert.equal(dropped.status.textContent, unconfirmed);
  // Cause and effect stay together: the sentence sits in the pressed row,
  // and focus returns to the pressed button.
  assert.deepEqual(dropped.row.children, [dropped.status]);
  assert.equal(dropped.button.focused, true);

  // An expired request says so and how to start again; the selection stays
  // until the reloaded page shows the signer's stored final refusal.
  const expired = page({answers: [() => { const e = new Error('Request refused'); e.status = 410;
    e.detail = 'operation_expired'; throw e; }]});
  await expired.button.events.click();
  assert.equal(expired.status.textContent,
    'This request expired without being carried out. Reload to request a new approval.');
  assert.ok(expired.store.has(key));
  const reloaded = page({finals: [JSON.parse(expired.store.get(key)).operation_id],
    stored: {[key]: expired.store.get(key)}, answers: [() => ({handoff_id: 'h-2'})]});
  await reloaded.button.events.click();
  assert.notEqual(reloaded.sent[0][1].operation_id, JSON.parse(expired.store.get(key)).operation_id,
    'the next Remove after a final expiry reused the old request');

  // Only a final history entry for the saved operation forgets it.
  const saved = JSON.stringify({operation_id: 'op-final', operation: 'team.agent.remove',
    variant: 'owner_approved', team_id: team, certificate_id: certificate});
  const other = `aweb.owner-removal:another-scope:${certificate}`;
  const kept = page({finals: ['op-other'], stored: {[key]: saved}, answers: []});
  assert.ok(kept.store.has(key));
  const forgotten = page({finals: ['op-final'], stored: {[key]: saved, [other]: saved}, answers: []});
  assert.ok(!forgotten.store.has(key), 'a final operation was not forgotten');
  assert.ok(forgotten.store.has(other), 'another approver or team lost its saved selection');
  // A selection older than the page's History: the page asks by exact id, and
  // only the signer's answer that it is final forgets it.
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const asked = page({stored: {[key]: saved}, answers: [() => ({final: ['op-final']})]});
  await settle();
  assert.deepEqual(asked.sent, [['/governance/operations/final', {operation_ids: ['op-final']}]]);
  assert.ok(!asked.store.has(key), 'a final operation the lookup named was not forgotten');
  const notFinal = page({stored: {[key]: saved}, answers: [() => ({final: []})]});
  await settle();
  assert.ok(notFinal.store.has(key), 'a selection the lookup did not name final was forgotten');
  const failed = page({stored: {[key]: saved}, answers: [lost]});
  await settle();
  assert.ok(failed.store.has(key), 'a failed lookup forgot a selection');
  // Fifty held selections that are not final, then one that is, off the page:
  // the page asks about all of them, in batches, and retires only the final one.
  const many = {};
  for (let i = 0; i < 50; i++) {
    many[`aweb.owner-removal:${scope}:cert-${i}`] = JSON.stringify({operation_id: `op-open-${i}`,
      operation: 'team.agent.remove', variant: 'owner_approved', team_id: team, certificate_id: `cert-${i}`});
  }
  many[key] = saved;
  const batched = page({stored: many, answers: [() => ({final: []}), () => ({final: ['op-final']})]});
  await settle();
  await settle();
  assert.equal(batched.sent.length, 2, 'the held selections were not all asked about');
  assert.ok(batched.sent.every(([path, body]) => path === '/governance/operations/final' &&
    body.operation_ids.length <= 50), 'a lookup named more than fifty');
  assert.ok(!batched.store.has(key), 'the final selection past the first fifty was not forgotten');
  for (let i = 0; i < 50; i++) assert.ok(batched.store.has(`aweb.owner-removal:${scope}:cert-${i}`));
  console.log('owner removal probe passed');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
