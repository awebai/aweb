// Execute the full page script and its actual immutable presentation validator
// with DOM/fetch ports. No browser, passkey or consumer execution is claimed.
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {webcrypto} = require('node:crypto');
const assert = require('node:assert/strict');
const fixture = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = fs.readFileSync('naapp-lib/src/aweb_naapp/console/browser/handoff.js', 'utf8')
  .replace(/^import .*;\n/gm, '');
const copy = value => JSON.parse(JSON.stringify(value));
const applied = () => ({v: 2, type: 'aweb.protected-delivery', artifact: copy(fixture.artifact),
  delivery: {mode: 'service_owned', state: 'applied', reference: {
    operation_id: fixture.state.operation_id, artifact_sha256: fixture.artifact_sha256}}});
(async () => {
  const moduleAt = name => pathToFileURL(path.resolve('naapp-lib/src/aweb_naapp/assets', name)).href;
  const {validateProtectedPresentation, validateProtectedReceiptPresentation} = await import(moduleAt('protected-presentation.mjs'));
  const {renderDisplay, displayRefusal} = await import(moduleAt('protected-display.mjs'));
  async function open(state) {
    const elements = new Map();
    const element = id => {
      if (!elements.has(id)) elements.set(id, {textContent: '', hidden: false, disabled: true,
        addEventListener() {}, focus() {}, replaceChildren() {}});
      return elements.get(id);
    };
    const reads = [];
    let finish;
    const finished = new Promise(resolve => {finish = resolve;});
    const dataset = new Proxy({handoffId: 'same-handoff', purpose: 'governance', consoleCsrfKey: 'csrf'}, {
      set(target, key, value) {
        target[key] = value;
        if (key === 'handoffState' && ['complete', 'login-required', 'refused'].includes(value)) finish();
        return true;
      }});
    const context = {URL, URLSearchParams, console, crypto: webcrypto, TextEncoder, Uint8Array, DataView, BigInt, atob, btoa,
      validateProtectedPresentation, validateProtectedReceiptPresentation, renderDisplay, displayRefusal,
      operationTable: fixture.table,
      document: {body: {dataset},
        getElementById: element, createElement: () => ({textContent: ''})},
      window: {location: {hash: '', pathname: '/handoff/same-handoff', origin: 'https://human.example'}},
      sessionStorage: {getItem: () => 'existing-session-token'},
      fetch: async (url, options) => {
        reads.push([url, options.method]);
        return {ok: true, json: async () => state};
      }};
    vm.runInNewContext(source, context, {filename: 'exact-handoff.js'});
    let timeout;
    try {
      await Promise.race([finished, new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('page did not settle')), 5000);
      })]);
    } finally {clearTimeout(timeout);}
    assert.deepEqual(reads, [['/handoff/same-handoff/governance', 'GET']]);
    assert.notEqual(element('handoff-action').textContent, 'Approve', 'terminal receipt enabled a new approval');
    return element('handoff-title').textContent;
  }
  const stateFor = result => ({...copy(fixture.state), result});
  assert.equal(await open(stateFor(applied())), 'Approved');
  assert.equal(await open(stateFor({signing: 'retained', signature: 'retained'})), 'Approved');
  for (const mutate of [r => {r.delivery.mode = 'client_owned';}, r => {delete r.delivery.mode;},
    r => {r.delivery.reference.operation_id = 'other-operation';}, r => {r.delivery.state = 'pending';},
    r => {r.delivery.reference.artifact_sha256 = 'not-a-digest';},
    r => {r.delivery.reference.artifact_sha256 = '0'.repeat(64);},
    r => {r.artifact.signing = Buffer.from('different retained bytes').toString('base64');},
    r => {r.artifact.signature = Buffer.alloc(64, 7).toString('base64');},
    r => {r.artifact.signature = 'bad base64';}, r => {r.v = 3;}]) {
    const result = applied(); mutate(result);
    assert.equal(await open(stateFor(result)), 'Not confirmed', JSON.stringify(result));
  }
  for (const corrupt of [s => {delete s.payload;}, s => {delete s.digest;}, s => {s.digest = '0'.repeat(64);},
    s => {s.payload.request.operation_id = 'other-operation';}, s => {s.operation_id = 'other-operation';},
    s => {s.payload.request.subject.expected_membership.alias = 'different target';}, s => {s.handoff_id = 'other-handoff';}]) {
    const state = stateFor(applied()); corrupt(state);
    assert.notEqual(await open(state), 'Approved', JSON.stringify(state));
  }
  assert.equal(await open({...copy(fixture.state), state: 'unknown'}), 'Not confirmed');
  await assert.rejects(validateProtectedPresentation(fixture.state, 'same-handoff', fixture.table), /handoff_refused/);
  console.log('retained handoff probe passed');
})().catch(error => {console.error(error.stack); process.exitCode = 1;});
