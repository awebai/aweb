import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSource, checkPrimitiveUses } from './check_identity_ts_inventory.mjs';
const observed=(source,file='pkg/consumer.ts')=>Object.entries(scanSource(source,file)).map(([symbol,calls])=>({file,symbol,calls}));
test('a new raw verifier refuses; a shared public helper call passes',()=>{
 assert.ok(checkPrimitiveUses(observed("import * as ed from '@noble/ed25519'; ed.verify(sig,msg,key);"),[]).length);
 assert.deepEqual(checkPrimitiveUses(observed("import { idEd25519Verify } from './identity/id_certificates.js'; idEd25519Verify(k,p,s);"),[]),[]);
});
test('only the named shared verifier and point predicate use raw primitives',()=>{
 for(const [file,symbol] of [['channel-core/src/identity/id_certificates.ts','idEd25519Verify'],['channel-core/src/identity/did.ts','primeSubgroupPoint']]) {
  assert.deepEqual(checkPrimitiveUses(observed(`import * as ed from '@noble/ed25519'; function ${symbol}(){ed.ExtendedPoint.fromHex(k);}`,file),[]),[]);
  assert.ok(checkPrimitiveUses(observed("import * as ed from '@noble/ed25519'; function bypass(){ed.verify(s,p,k);}",file),[]).length);
 }
});
test('legacy reasons allow repeated calls without a count catalog',()=>{
 const file='pkg/legacy.ts',source="import * as ed from '@noble/ed25519'; ed.sign(p,k); ed.sign(q,k);";
 assert.deepEqual(checkPrimitiveUses(observed(source,file),[{file,reason:'Existing released message signature family.'}]),[]);
 assert.ok(checkPrimitiveUses(observed(source,file),[{file,reason:''}]).length);
});
test('references, createRequire and WebCrypto roots are classified as their modules',()=>{
 for(const source of ["import * as ed from '@noble/ed25519'; callback(ed.verify);", "import { createRequire } from 'node:module'; const load=createRequire(import.meta.url); const crypto=load('node:crypto'); crypto.verify(a,b,c,d);", ...['crypto','globalThis.crypto','self.crypto','window.crypto'].map(root=>`${root}.subtle.verify(a,b,c,d);`)])assert.ok(checkPrimitiveUses(observed(source),[]).length,source);
});
test('ordinary hashes are outside the Ed25519 boundary',()=>{
 assert.deepEqual(checkPrimitiveUses(observed("import { createHash } from 'node:crypto'; createHash('sha256').update(p).digest();"),[]),[]);
});
