import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanSource, scanRepository, checkCatalog, excluded, exportedIdentityAPI } from './check_identity_ts_inventory.mjs';

for (const [label, source, symbol, callee] of [
 ['namespace alias', 'import * as ed from "@noble/ed25519"; function f(){ed.verify(a,b,c)}', 'f', '@noble/ed25519.verify'],
 ['named alias', 'import { verify as check } from "@noble/ed25519"; function f(){check(a,b,c)}', 'f', '@noble/ed25519.verify'],
 ['callback', 'import * as ed from "@noble/ed25519"; function f(){run(ed.verify)}', 'f', 'reference:@noble/ed25519.verify'],
 ['CommonJS namespace', 'const ed = require("node:crypto"); function f(){ed.verify(a,b,c)}', 'f', 'node:crypto.verify'],
 ['CommonJS named alias', 'const { verify: check } = require("crypto"); function f(){check(a,b,c)}', 'f', 'crypto.verify'],
 ['destructured namespace', 'import * as ed from "@noble/ed25519"; const {verify:check}=ed; function f(){check(a,b,c)}', 'f', '@noble/ed25519.verify'],
 ['CommonJS member namespace', 'const ed=require("@noble/curves/ed25519").ed25519; function f(){ed.Point.fromHex(a)}', 'f', '@noble/curves/ed25519.ed25519.Point.fromHex'],
 ['named re-export', 'export {verify as check} from "@noble/ed25519"', '<module>', 'reference:@noble/ed25519.verify'],
 ['DID constant', 'const prefix = "did:key:z"; function f(){return prefix+x}', '<module>', 'literal:did:key'],
 ['method', 'class C { check(){verifyMessage(x)} }', 'C.check', 'verifyMessage'],
 ['arrow', 'const f = () => verifyIdChain(x)', 'f', 'verifyIdChain'],
 ['curve arithmetic', 'import * as ed from "@noble/ed25519"; function f(){ed.Point.fromHex(x)}', 'f', '@noble/ed25519.Point.fromHex'],
 ['crypto key constructor', 'import {createPublicKey as key} from "node:crypto"; function f(){key(x)}', 'f', 'node:crypto.createPublicKey'],
 ['rotation', 'function f(){client.rotateKey(x)}', 'f', 'client.rotateKey'],
 ['keypair', 'function f(){GenerateKeypair()}', 'f', 'GenerateKeypair'],
 ['closure', 'function f(){run(()=>verifyIdChain(x))}', 'f', 'verifyIdChain'],
]) test(label, () => assert.equal(scanSource(source)[symbol][callee], 1));

test('comments and type-only names are not executable uses', () => {
 assert.deepEqual(scanSource('// did:key:z\nimport type {VerifyResult} from "x"; type T = VerifyResult; function f(){console.log("ordinary")}'), {});
});

test('catalog pins exact calls and strict verifier use', () => {
 const file='channel-core/src/identity/id_certificates.ts';
 const entry={row:'r',file,symbol:'f',calls:{'@noble/ed25519.verify':1}};
 const row={id:'r',repo:'aweb',files:[file],sites:[{file,symbol:'f'}],ed25519_profile:'strict'};
 const observed=[{file,symbol:'f',calls:entry.calls}];
 assert.match(checkCatalog([row],[entry],observed).join('\n'),/shared strict/);
 assert.match(checkCatalog([{...row,ed25519_profile:'legacy'}],[entry],observed).join('\n'),/downgrade/);
 const legacyFile='new/package/identity.ts';
 const legacy={...row,files:[legacyFile],sites:[{file:legacyFile,symbol:'f'}],ed25519_profile:'legacy'};
 const declared={...entry,file:legacyFile};const actual=[{file:legacyFile,symbol:'f',calls:entry.calls}];
 assert.deepEqual(checkCatalog([legacy],[declared],actual),[]);
 assert.match(checkCatalog([legacy],[],actual).join('\n'),/unlisted/);
 assert.match(checkCatalog([legacy],[declared],[]).join('\n'),/stale/);
 assert.match(checkCatalog([legacy],[declared,declared],actual).join('\n'),/duplicate/);
 assert.match(checkCatalog([legacy],[declared],[{...actual[0],calls:{'@noble/ed25519.verify':2}}]).join('\n'),/changed/);
 assert.match(checkCatalog([{...legacy,sites:[]}],[declared],actual).join('\n'),/mapped exact/);
});

test('new package cannot escape source discovery', () => {
 const root=mkdtempSync(path.join(tmpdir(),'identity-ts-'));
 try {
  execFileSync('git',['init','--quiet'],{cwd:root});mkdirSync(path.join(root,'new','src'),{recursive:true});
  writeFileSync(path.join(root,'new','src','identity.ts'),'import * as ed from "@noble/ed25519"; export const f=()=>ed.verify(a,b,c)');
  const observed=scanRepository(root);
  assert.equal(observed[0].file,'new/src/identity.ts');
  assert.match(checkCatalog([],[],observed).join('\n'),/unlisted/);
 } finally {rmSync(root,{recursive:true,force:true});}
});

test('production test names under src stay scanned', () => {
 for(const file of ['new/src/test_identity.ts','new/src/test/identity.ts','new/src/x.mjs']) assert.equal(excluded(file),false);
 for(const file of ['new/src/tests/x.ts','channel-core/test/a.test.ts','scripts/test_check_identity_ts_inventory.mjs','new/types.d.ts']) assert.equal(excluded(file),true);
});

test('wildcard primitive export refuses',()=>assert.throws(()=>scanSource('export * from "@noble/ed25519"'),/wildcard export/));

test('public identity APIs are derived from their source',()=>{
 const names=exportedIdentityAPI('export function computeStableID(){}; export class Keys { loadKeys(){}; private hidden(){} }','keys.ts');
 assert.equal(names.has('computeStableID'),true);assert.equal(names.has('loadKeys'),true);assert.equal(names.has('hidden'),false);
 const got=scanSource('import {computeStableID as derive} from "./did.js"; function f(){derive(x)}','consumer.ts',names);
 assert.equal(got.f['./did.js.computeStableID'],1);
});
