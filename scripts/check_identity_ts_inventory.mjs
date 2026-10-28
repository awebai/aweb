#!/usr/bin/env node
// S8b syntactic drift guard for TypeScript and JavaScript identity primitives.
// It does not attempt reflection or whole-program data-flow analysis.
import { createRequire } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const defaultRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(path.join(defaultRoot,'channel-core/package.json'));
const ts=require('typescript'); // The existing channel-core lockfile pins the parser.
const strictModules=new Set(['channel-core/src/identity/id_certificates.ts','channel-core/src/identity/id_verification.ts']);
// The shared strict point predicate and the did:key decoder that applies it
// live in did.ts, beside legacy helpers; these sites, the functions nested in
// them, and the decoder as bundled into the wake runner must stay strict.
const didModule='channel-core/src/identity/did.ts';
const strictSites=[
 [didModule,'primeSubgroupPoint'],
 [didModule,'extractPublicKey'],
 ['cli/go/wake/channel_core_runner_bundle.mjs','extractPublicKey'],
];
function strictSite(entry) {
 return strictSites.some(([file,symbol])=>entry.file===file && (entry.symbol===symbol || entry.symbol.startsWith(symbol+'.')));
}
// did.ts holds the one raw point decode, exactly in primeSubgroupPoint; any
// other raw Ed25519 or curve use there refuses whatever its row's profile.
function rawCurve(callee) {
 const name=callee.replace(/^reference:/,'');
 return rawVerifier(callee) || ['@noble/ed25519','@noble/curves','tweetnacl','libsodium-wrappers'].some(prefix=>name.startsWith(prefix));
}
const extensions=/\.(?:[cm]?[jt]s|[jt]sx)$/;
const nameFamily=/^(?:(?:[sS]ign|[vV]erify|[rR]egister|[rR]evoke|[rR]otate)(?=$|[_A-Z])|(?:id(?:Ed25519|Certificate|Chain|Status|Request)|[gG]enerateKey|randomPrivateKey|getPublicKey|publicKeyToDID|didKeyFromPublicKey|parseDIDKey|encodeIdChain|decodeIdChain|prepareHumanKey|createIdentity))/;

export function excluded(file) {
 const parts=file.split('/');const name=parts.at(-1);
 if (/\.d\.[cm]?ts$/.test(name)) return true;
 if (parts.includes('src')) return parts.slice(parts.indexOf('src')+1,-1).includes('tests');
 return file==='scripts/check_identity_ts_inventory.mjs' || parts.slice(0,-1).some(p=>['test','tests','testdata','fixtures'].includes(p)) || /(?:\.test\.|\.spec\.|^test[-_])/.test(name);
}
function primitiveModule(name) {
 return ['@noble/ed25519', '@noble/curves', 'tweetnacl', 'libsodium-wrappers'].some(prefix=>name.startsWith(prefix)) || /^(?:node:crypto|crypto)(?:$|[./])/.test(name);
}
function primitive(name) {return primitiveModule(name) || nameFamily.test(name.split('.').at(-1));}
function rawVerifier(name) {
 name=name.replace(/^reference:/,'');
 return primitiveModule(name) && /(?:verify|verifyAsync|createVerify|open)$/.test(name) || /(?:^|\.)(?:verifyMessage|verifySignedPayload|VerifyKey|Ed25519PublicKey)$/.test(name);
}

export function exportedIdentityAPI(source,file) {
 const tree=ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true);const names=new Set();
 for(const node of tree.statements) {
  if(!node.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))continue;
  if((ts.isFunctionDeclaration(node)||ts.isClassDeclaration(node)) && node.name)names.add(node.name.text);
  if(ts.isClassDeclaration(node))for(const member of node.members)if(ts.isMethodDeclaration(member) && !member.modifiers?.some(m=>[ts.SyntaxKind.PrivateKeyword,ts.SyntaxKind.ProtectedKeyword].includes(m.kind)) && ts.isIdentifier(member.name))names.add(member.name.text);
  if(ts.isVariableStatement(node))for(const declaration of node.declarationList.declarations)if(ts.isIdentifier(declaration.name) && declaration.initializer && (ts.isArrowFunction(declaration.initializer)||ts.isFunctionExpression(declaration.initializer)))names.add(declaration.name.text);
 }
 return names;
}
export function scanSource(source, file='fixture.ts', identityAPI=new Set()) {
 const isPrimitive=name=>primitive(name)||identityAPI.has(name.split('.').at(-1));
 const kind=file.endsWith('.tsx')?ts.ScriptKind.TSX:file.endsWith('.jsx')?ts.ScriptKind.JSX:/\.[cm]?js$/.test(file)?ts.ScriptKind.JS:ts.ScriptKind.TS;
 const tree=ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true,kind);
 if(tree.parseDiagnostics.length) throw new Error(ts.flattenDiagnosticMessageText(tree.parseDiagnostics[0].messageText,' '));
 const aliases=new Map();
 const requireFunctions=new Set(["require"]);
 function moduleValue(node) {
  if(!node)return null;
  if(ts.isIdentifier(node))return aliases.get(node.text)??null;
  if(ts.isCallExpression(node) && ts.isIdentifier(node.expression) && requireFunctions.has(node.expression.text) && node.arguments.length===1 && ts.isStringLiteral(node.arguments[0]))return node.arguments[0].text;
  if(ts.isPropertyAccessExpression(node)){const base=moduleValue(node.expression);return base?base+'.'+node.name.text:null;}
  return null;
 }
 function importAliases(node) {
  if(ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && node.importClause && !node.importClause.isTypeOnly) {
   const module=node.moduleSpecifier.text;const clause=node.importClause;
   if(clause.name) aliases.set(clause.name.text,module);
   const bindings=clause.namedBindings;
   if(bindings && ts.isNamespaceImport(bindings)) aliases.set(bindings.name.text,module);
   if(bindings && ts.isNamedImports(bindings)) for(const item of bindings.elements) if(!item.isTypeOnly) aliases.set(item.name.text,module+'.'+(item.propertyName??item.name).text);
  }
  if(ts.isVariableDeclaration(node)) {
   if(ts.isIdentifier(node.name) && node.initializer && ts.isCallExpression(node.initializer) && moduleValue(node.initializer.expression)==='node:module.createRequire')requireFunctions.add(node.name.text);
   const module=moduleValue(node.initializer);
   if(module && ts.isIdentifier(node.name))aliases.set(node.name.text,module);
   if(module && ts.isObjectBindingPattern(node.name))for(const element of node.name.elements)if(ts.isIdentifier(element.name))aliases.set(element.name.text,module+'.'+(element.propertyName??element.name).text);
  }
  ts.forEachChild(node,importAliases);
 }
 importAliases(tree);
 const name=node=>{
  if(!node)return '<expression>';
  if(ts.isIdentifier(node))return aliases.get(node.text)??node.text;
  if(ts.isPropertyAccessExpression(node))return name(node.expression)+'.'+node.name.text;
  if(ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteral(node.argumentExpression))return name(node.expression)+'.'+node.argumentExpression.text;
  if(ts.isCallExpression(node) || ts.isNewExpression(node))return name(node.expression)+'()';
  if(ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node) || ts.isAsExpression(node))return name(node.expression);
  return '<expression>';
 };
 const result={};
 const record=(scope,callee)=>{const symbol=scope.join('.')||'<module>';result[symbol]??={};result[symbol][callee]=(result[symbol][callee]??0)+1;};
 function visit(node,scope=[]) {
  if(ts.isTypeNode(node) || ts.isImportDeclaration(node) || ts.isImportEqualsDeclaration(node))return;
  if(ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
   const module=node.moduleSpecifier.text;
   if(!node.exportClause && primitiveModule(module+'.'))throw new Error('wildcard export hides identity primitive: '+module);
   if(node.exportClause && ts.isNamedExports(node.exportClause) && !node.isTypeOnly)for(const element of node.exportClause.elements) {
    const callee=module+'.'+(element.propertyName??element.name).text;
    if(!element.isTypeOnly && isPrimitive(callee))record(scope,'reference:'+callee);
   }
   return;
  }
  if(ts.isCallExpression(node) && node.expression.kind===ts.SyntaxKind.ImportKeyword && node.arguments.length && ts.isStringLiteral(node.arguments[0]) && primitiveModule(node.arguments[0].text+'.'))throw new Error('dynamic import hides identity primitive: '+node.arguments[0].text);
  let next=scope;
  if(ts.isClassDeclaration(node) || ts.isClassExpression(node) || ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node)) {
   let label=node.name?.getText(tree);
   if(!label && ts.isArrowFunction(node) && ts.isVariableDeclaration(node.parent))label=node.parent.name.getText(tree);
   if(label)next=[...scope,label];
  }
  if(ts.isCallExpression(node) || ts.isNewExpression(node)) {const callee=name(node.expression);if(isPrimitive(callee))record(next,callee);}
  if(ts.isIdentifier(node) || ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
   const parent=node.parent;
   const callee=(ts.isCallExpression(parent)||ts.isNewExpression(parent)) && parent.expression===node;
   const receiver=ts.isPropertyAccessExpression(parent)||ts.isElementAccessExpression(parent);
   const definition=(ts.isVariableDeclaration(parent)||ts.isFunctionDeclaration(parent)||ts.isFunctionExpression(parent)||ts.isClassDeclaration(parent)||ts.isMethodDeclaration(parent)||ts.isParameter(parent)||ts.isPropertyDeclaration(parent)||ts.isPropertyAssignment(parent)||ts.isBindingElement(parent)) && parent.name===node;
   if(!callee && !receiver && !definition){const ref=name(node);if(isPrimitive(ref))record(next,'reference:'+ref);}
  }
  if(ts.isStringLiteral(node)||ts.isNoSubstitutionTemplateLiteral(node)||ts.isTemplateHead(node)) {
   for(const prefix of ['did:key','did:aw'])if(node.text.startsWith(prefix+':'))record(next,'literal:'+prefix);
   if(primitiveModule(node.text))record(next,'module-literal:'+node.text);
  }
  ts.forEachChild(node,child=>visit(child,next));
 }
 visit(tree);
 return result;
}

export function scanRepository(root) {
 const output=execFileSync('git',['ls-files','-z','--cached','--others','--exclude-standard','--','*.ts','*.tsx','*.mts','*.cts','*.js','*.jsx','*.mjs','*.cjs'],{cwd:root,encoding:'utf8'});
 const identityAPI=new Set();
 for(const file of output.split("\0"))if(file.startsWith("channel-core/src/identity/") && extensions.test(file) && !excluded(file) && existsSync(path.join(root,file)))for(const name of exportedIdentityAPI(readFileSync(path.join(root,file),"utf8"),file))identityAPI.add(name);
 const sites=[];
 for(const file of [...new Set(output.split('\0'))].sort()) {
  if(!file || !extensions.test(file) || excluded(file) || !existsSync(path.join(root,file)))continue;
  let parsed;try{parsed=scanSource(readFileSync(path.join(root,file),'utf8'),file,identityAPI);}catch(error){throw new Error(`cannot scan ${file}: ${error.message}`);}
  for(const [symbol,calls] of Object.entries(parsed))sites.push({file,symbol,calls});
 }
 return sites;
}

function disallowedStrictPrimitive(entry,callee) {
 if(rawVerifier(callee))return true;
 const name=callee.replace(/^reference:/,'');
 if(!primitiveModule(name))return false;
 const codec=entry.file==='channel-core/src/identity/id_certificates.ts';
 if(codec && entry.symbol==='idEd25519Verify')return false;
 if(entry.file===didModule && entry.symbol==='primeSubgroupPoint')return false;
 // Hash wiring and the group-order constant in the reviewed codec are not a
 // second verifier. These exact uses are still pinned by the source catalog.
 if(codec && entry.symbol==='<module>' && ['reference:@noble/ed25519.etc.sha512Sync','@noble/ed25519.etc.concatBytes','reference:@noble/ed25519.CURVE.n'].includes(callee))return false;
 return true;
}

export function checkCatalog(rows,entries,observed) {
 const errors=[];const byID=new Map();
 for(const row of rows){if(!row.id || byID.has(row.id))errors.push('missing or duplicate inventory row '+row.id);byID.set(row.id,row);}
 const declared=new Map();const actual=new Map();
 const key=entry=>JSON.stringify([entry.file,entry.symbol]);
 for(const entry of entries) {
  if(!entry || !isDeepStrictEqual(Object.keys(entry).sort(),['calls','file','row','symbol']) || typeof entry.file!=='string' || typeof entry.symbol!=='string' || !entry.symbol || path.posix.normalize(entry.file)!==entry.file || entry.file.startsWith('/') || entry.file.startsWith('../') || !extensions.test(entry.file) || excluded(entry.file)) {errors.push('invalid TS catalog entry');continue;}
  if(declared.has(key(entry)))errors.push('duplicate TS catalog site '+key(entry));declared.set(key(entry),entry.calls);
  if(!entry.calls || typeof entry.calls!=='object' || Array.isArray(entry.calls) || !Object.keys(entry.calls).length || Object.entries(entry.calls).some(([callee,n])=>!callee || !Number.isSafeInteger(n) || n<1))errors.push('invalid TS primitive counts '+key(entry));
  const row=byID.get(entry.row);
  if(row?.repo!=='aweb' || !row.files?.includes(entry.file) || !row.sites?.some(site=>site.file===entry.file && site.symbol===entry.symbol))errors.push('TS primitive needs mapped exact site '+key(entry));
  if(!['strict','legacy'].includes(row?.ed25519_profile))errors.push('TS row requires strict|legacy profile '+entry.row);
  if((strictModules.has(entry.file) || strictSite(entry)) && row?.ed25519_profile!=='strict')errors.push('ID module cannot downgrade strict profile '+key(entry));
  if(entry.file===didModule && entry.symbol!=='primeSubgroupPoint' && entry.calls && Object.keys(entry.calls).some(rawCurve))errors.push('raw curve use in did.ts outside primeSubgroupPoint '+key(entry));
  if(row?.ed25519_profile==='strict' && entry.calls && Object.keys(entry.calls).some(callee=>disallowedStrictPrimitive(entry,callee)))errors.push('raw ID crypto must use shared strict verifier '+key(entry));
 }
 for(const entry of observed){actual.set(key(entry),entry.calls);if(!declared.has(key(entry)))errors.push('unlisted TS identity primitive site '+key(entry));else if(!isDeepStrictEqual(declared.get(key(entry)),entry.calls))errors.push('TS primitive counts changed '+key(entry));}
 for(const entry of declared.keys())if(!actual.has(entry))errors.push('stale TS identity primitive site '+entry);
 return errors.sort();
}

export function checkInventory(root) {
 const inventory=JSON.parse(readFileSync(path.join(root,'docs/identity-tree-coverage.json'),'utf8'));
 if(inventory.v!==1 || inventory.ts_guard?.v!==1 || !Array.isArray(inventory.ts_guard.sites))throw new Error('identity inventory requires v=1 and ts_guard {v:1,sites:[]}');
 return checkCatalog(inventory.sites,inventory.ts_guard.sites,scanRepository(root));
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 try {
  if(process.argv.length!==2)throw new Error('usage: check_identity_ts_inventory.mjs');
  const errors=checkInventory(defaultRoot);if(errors.length)throw new Error(errors.join('\n'));
  console.log('TypeScript/JavaScript identity primitive inventory passed; S8b release qualification remains separate');
 }catch(error){console.error(error.message);process.exitCode=1;}
}
