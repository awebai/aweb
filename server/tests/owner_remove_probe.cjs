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

function page({finals = [], stored = {}, answers}) {
  const store = new Map(Object.entries(stored));
  const sessionStorage = {
    getItem: k => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: k => store.delete(k),
    key: i => [...store.keys()][i] ?? null,
    get length() { return store.size; },
  };
  const button = {dataset: {removeCertificate: certificate}, disabled: false, events: {},
    addEventListener(name, fn) { this.events[name] = fn; }};
  const status = {textContent: ''};
  const list = {dataset: {teamId: team, storageScope: scope},
    querySelectorAll: selector => (selector === '[data-remove-certificate]' ? [button] : [])};
  const finalItems = finals.map(id => ({dataset: {finalOperation: id}}));
  const sent = [];
  const storedAtSend = [];
  const assigned = [];
  let uuids = 0;
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
  return {button, status, sent, storedAtSend, assigned, store};
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

  // An error tells the person, keeps the button usable and the selection kept.
  const q = page({answers: [refusal('subject_ineligible')]});
  await q.button.events.click();
  assert.equal(q.button.disabled, false);
  assert.ok(q.store.has(key) && q.status.textContent.length > 0);

  // Only a final history entry for the saved operation forgets it.
  const saved = JSON.stringify({operation_id: 'op-final', operation: 'team.agent.remove',
    variant: 'owner_approved', team_id: team, certificate_id: certificate});
  const other = `aweb.owner-removal:another-scope:${certificate}`;
  const kept = page({finals: ['op-other'], stored: {[key]: saved}, answers: []});
  assert.ok(kept.store.has(key));
  const forgotten = page({finals: ['op-final'], stored: {[key]: saved, [other]: saved}, answers: []});
  assert.ok(!forgotten.store.has(key), 'a final operation was not forgotten');
  assert.ok(forgotten.store.has(other), 'another approver or team lost its saved selection');
  console.log('owner removal probe passed');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
