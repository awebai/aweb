import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanSource, checkPrimitiveUses, checkInventory } from './check_identity_ts_inventory.mjs';
const observed=(source,file='pkg/consumer.ts')=>Object.entries(scanSource(source,file)).map(([symbol,calls])=>({file,symbol,calls}));

const sourceImport = "import * as ed from '@noble/ed25519'; ";
const exemption = {file:'consumer.ts', symbol:'check', callee:'@noble/ed25519.verify', reason:'Existing signed family.'};
for (const {name, source, entries = [exemption], want} of [
 {name:'unused', source:'function check(){}', want:'unused primitive exemption: consumer.ts:check: @noble/ed25519.verify'},
 {name:'missing file', want:'listed source file consumer.ts is missing'},
 {name:'one call', source:'function check(){ed.verify(k,p,s);}'},
 {name:'second call', source:'function check(){ed.verify(k,p,s); ed.verify(k,q,s);}', want:'primitive exemption matches 2 calls: consumer.ts:check: @noble/ed25519.verify'},
 {name:'different symbol', source:'function check(){ed.verify(k,p,s);} function other(){ed.verify(k,p,s);}', want:'raw TS crypto must use the shared verifier: consumer.ts:other: @noble/ed25519.verify'},
 {name:'duplicate', source:'function check(){ed.verify(k,p,s);}', entries:[exemption, exemption], want:'duplicate primitive exemption: consumer.ts:check: @noble/ed25519.verify'},
 {name:'blank reason', source:'function check(){ed.verify(k,p,s);}', entries:[{...exemption, reason:' '}], want:'primitive exemption requires file, symbol, callee and reason'},
 {name:'reference', source:'function check(){callback(ed.verify);}', entries:[{...exemption, callee:'reference:@noble/ed25519.verify'}], want:'primitive exemption must name a call: consumer.ts:check: reference:@noble/ed25519.verify'},
]) {
 test(`inventory exemption: ${name}`, () => {
  const root = mkdtempSync(join(tmpdir(), 'aweb-ts-inventory-'));
  try {
   execFileSync('git', ['init', '-q', root]);
   if (source) writeFileSync(join(root, 'consumer.ts'), sourceImport + source);
   mkdirSync(join(root, 'docs'));
   writeFileSync(join(root, 'docs', 'identity-tree-coverage.json'), JSON.stringify({primitive_guard:{exempt_calls:entries}}));
   const errors = checkInventory(root);
   if (want) assert.ok(errors.includes(want), errors.join('\n'));
   else assert.deepEqual(errors, []);
  } finally {
   rmSync(root, {recursive:true, force:true});
  }
 });
}
test('a new raw verifier refuses; a shared public helper call passes',()=>{
 assert.ok(checkPrimitiveUses(observed("import * as ed from '@noble/ed25519'; ed.verify(sig,msg,key);"),[]).length);
 assert.deepEqual(checkPrimitiveUses(observed("import { idEd25519Verify } from './identity/id_certificates.js'; idEd25519Verify(k,p,s);"),[]),[]);
});
test('only the named shared verifier and point predicate use raw primitives',()=>{
 for(const [file,symbol] of [['packages/channel-core/src/identity/signature_wire.ts','verifyBytes'],['packages/channel-core/src/identity/signature_wire.ts','primeSubgroupPoint']]) {
  assert.deepEqual(checkPrimitiveUses(observed(`import * as ed from '@noble/ed25519'; function ${symbol}(){ed.ExtendedPoint.fromHex(k);}`,file),[]),[]);
  assert.ok(checkPrimitiveUses(observed("import * as ed from '@noble/ed25519'; function bypass(){ed.verify(s,p,k);}",file),[]).length);
 }
});
test('references, createRequire and WebCrypto roots are classified as their modules',()=>{
 for(const source of ["import * as ed from '@noble/ed25519'; callback(ed.verify);", "import { createRequire } from 'node:module'; const load=createRequire(import.meta.url); const crypto=load('node:crypto'); crypto.verify(a,b,c,d);", ...['crypto','globalThis.crypto','self.crypto','window.crypto'].map(root=>`${root}.subtle.verify(a,b,c,d);`)])assert.ok(checkPrimitiveUses(observed(source),[]).length,source);
});
test('ordinary hashes are outside the Ed25519 boundary',()=>{
 assert.deepEqual(checkPrimitiveUses(observed("import { createHash } from 'node:crypto'; createHash('sha256').update(p).digest();"),[]),[]);
});

for (const { label, source, callee } of [
 { label: 'named Node WebCrypto import', source: "import { webcrypto } from 'node:crypto'; webcrypto.subtle.sign(a,k,m);", callee: 'node:crypto.webcrypto.subtle.sign' },
 { label: 'SubtleCrypto alias', source: 'const s = crypto.subtle; s.sign(a,k,m);', callee: 'crypto.subtle.sign' },
 { label: 'destructured SubtleCrypto', source: 'const { subtle } = crypto; subtle.sign(a,k,m);', callee: 'crypto.subtle.sign' },
]) {
 test(`raw WebCrypto signing through a ${label} refuses`, () => {
  assert.deepEqual(checkPrimitiveUses(observed(source), []), [
   `raw TS crypto must use the shared verifier: pkg/consumer.ts:<module>: ${callee}`,
  ]);
 });
}

test('SubtleCrypto digest and a local signer are outside the Ed25519 boundary', () => {
 const source = 'const { subtle } = globalThis.crypto; subtle.digest("SHA-256", m); const local = thing.subtle; local.sign(a,k,m);';
 assert.deepEqual(checkPrimitiveUses(observed(source), []), []);
});
