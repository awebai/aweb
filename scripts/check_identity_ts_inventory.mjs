#!/usr/bin/env node
// Raw primitive boundary and call exemptions for TypeScript and JavaScript.
// It does not attempt reflection or whole-program data-flow analysis.
import { createRequire } from 'node:module';
import { readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(path.join(defaultRoot,'packages/channel-core/package.json'));
const ts=require('typescript'); // The existing channel-core lockfile pins the parser.
const extensions=/\.(?:[cm]?[jt]s|[jt]sx)$/;


export function excluded(file) {
 const parts=file.split('/');const name=parts.at(-1);
 if (/\.d\.[cm]?ts$/.test(name)) return true;
 if (parts.includes('src')) return parts.slice(parts.indexOf('src')+1,-1).includes('tests');
 return file==='scripts/check_identity_ts_inventory.mjs' || parts.slice(0,-1).some(p=>['test','tests','testdata','fixtures'].includes(p)) || /(?:\.test\.|\.spec\.|^test[-_])/.test(name);
}
function primitiveModule(name) {
 return ['@noble/ed25519', '@noble/curves', 'tweetnacl', 'libsodium-wrappers'].some(prefix=>name.startsWith(prefix)) || /^(?:node:crypto|crypto)(?:$|[./])/.test(name);
}
function primitive(name) {return primitiveModule(name);}
const normalized=name=>name
 .replace(/^(?:reference:|module-literal:)/,'')
 .replace(/^(?:globalThis|self|window)\.crypto(?=\.|$)/,'crypto')
 .replace(/^(?:node:crypto|crypto)\.webcrypto\.subtle(?=\.|$)/,'crypto.subtle');
function rawUse(name) {
 name=normalized(name);
 if(!primitiveModule(name))return false;
 if(/^(?:node:crypto|crypto)(?:$|\.)/.test(name))return /^(?:node:crypto|crypto)\.(?:sign|verify|createSign|createVerify|generateKeyPair(?:Sync)?|createPrivateKey|createPublicKey|subtle\.(?:sign|verify|generateKey|importKey|exportKey))(?:$|[.(])/.test(name);
 return true;
}

export function scanSource(source, file='fixture.ts') {
 const isPrimitive=name=>primitive(normalized(name));
 const kind=file.endsWith('.tsx')?ts.ScriptKind.TSX:file.endsWith('.jsx')?ts.ScriptKind.JSX:/\.[cm]?js$/.test(file)?ts.ScriptKind.JS:ts.ScriptKind.TS;
 const tree=ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true,kind);
 if(tree.parseDiagnostics.length) throw new Error(ts.flattenDiagnosticMessageText(tree.parseDiagnostics[0].messageText,' '));
 const aliases=new Map();
 const requireFunctions=new Set(["require"]);
 function moduleValue(node) {
  if(!node)return null;
  if(ts.isIdentifier(node)) {
   if(aliases.has(node.text))return aliases.get(node.text);
   if(['crypto','globalThis','self','window'].includes(node.text))return node.text;
   return null;
  }
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
 const result=Object.create(null);
 const record=(scope,callee)=>{
  const symbol=scope.join('.')||'<module>';
  const calls=result[symbol]??=Object.create(null);
  calls[callee]=(calls[callee]??0)+1;
 };
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
   if(primitiveModule(node.text))record(next,'module-literal:'+node.text);
  }
  ts.forEachChild(node,child=>visit(child,next));
 }
 visit(tree);
 return result;
}

export function scanRepository(root) {
 const output=execFileSync('git',['ls-files','-z','--cached','--others','--exclude-standard','--','*.ts','*.tsx','*.mts','*.cts','*.js','*.jsx','*.mjs','*.cjs'],{cwd:root,encoding:'utf8'});
 const sites=[];
 for(const file of [...new Set(output.split('\0'))].sort()) {
  if(!file || !extensions.test(file) || excluded(file))continue;
  let parsed;try{parsed=scanSource(readFileSync(path.join(root,file),'utf8'),file);}catch(error){throw new Error(`cannot scan ${file}: ${error.message}`);}
  for(const [symbol,calls] of Object.entries(parsed))sites.push({file,symbol,calls});
 }
 return sites;
}

const locator=(file,symbol,callee)=>JSON.stringify([file,symbol,callee]);
const location=(file,symbol,callee)=>`${file}:${symbol}: ${callee}`;

export function checkPrimitiveUses(observed,exemptions) {
 const errors=[];
 const matches=new Map();
 for(const {file,symbol,callee,reason} of exemptions) {
  if([file,symbol,callee,reason].some(value=>typeof value!=='string' || !value.trim())) {
   errors.push('primitive exemption requires file, symbol, callee and reason');
   continue;
  }
  const site=location(file,symbol,callee);
  if(/^(?:reference:|module-literal:)/.test(callee) || !rawUse(callee)) {
   errors.push(`primitive exemption must name a call: ${site}`);
   continue;
  }
  const key=locator(file,symbol,callee);
  if(matches.has(key)) {
   errors.push(`duplicate primitive exemption: ${site}`);
   continue;
  }
  matches.set(key,{site,count:0});
 }
 for(const entry of observed)for(const [callee,count] of Object.entries(entry.calls)) {
  if(!rawUse(callee))continue;
  const codec=entry.file==='packages/channel-core/src/identity/signature_wire.ts';
  const name=normalized(callee);
  if(codec && ['verifyBytes','signBytes','publicKeyFromSeed','primeSubgroupPoint','canonicalPoint'].includes(entry.symbol))continue;
  if(codec && entry.symbol==='<module>' && ['@noble/ed25519.etc.sha512Sync','@noble/ed25519.etc.concatBytes'].includes(name))continue;
  const exemption=matches.get(locator(entry.file,entry.symbol,callee));
  if(exemption)exemption.count+=count;
  else errors.push(`raw TS crypto must use the shared verifier: ${location(entry.file,entry.symbol,callee)}`);
 }
 for(const {site,count} of matches.values()) {
  if(count===0)errors.push(`unused primitive exemption: ${site}`);
  else if(count!==1)errors.push(`primitive exemption matches ${count} calls: ${site}`);
 }
 return errors.sort();
}

function listedFileError(root,file) {
 if(path.isAbsolute(file) || path.posix.normalize(file)!==file || file.startsWith('../')) {
  return `listed source file must be a repository-relative path: ${file}`;
 }
 try {
  if(!statSync(path.join(root,file)).isFile())return `listed source file ${file} must be a regular file`;
 } catch(error) {
  if(error.code!=='ENOENT')throw error;
  return `listed source file ${file} is missing`;
 }
}

export function checkInventory(root) {
 const inventory=JSON.parse(readFileSync(path.join(root,'docs/identity-tree-coverage.json'),'utf8'));
 const entries=inventory.primitive_guard?.exempt_calls;
 if(!Array.isArray(entries))return ['primitive_guard.exempt_calls must be an array'];
 if(entries.some(entry=>typeof entry?.file!=='string' || !(extensions.test(entry.file) || /\.(?:go|py)$/.test(entry.file)))) {
  return ['primitive exemption must name a Go, Python, TypeScript or JavaScript source file'];
 }
 const exemptions=entries.filter(entry=>extensions.test(entry.file));
 const creationFiles=(inventory.creation_paths??[]).filter(row=>row.repo==='aweb').flatMap(row=>row.files);
 const files=new Set([...exemptions.map(entry=>entry.file),...creationFiles.filter(file=>extensions.test(file))]);
 const errors=[...files].map(file=>listedFileError(root,file)).filter(Boolean);
 return errors.length ? errors : checkPrimitiveUses(scanRepository(root),exemptions);
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 try {
  if(process.argv.length!==2)throw new Error('usage: check_identity_ts_inventory.mjs');
  const errors=checkInventory(defaultRoot);if(errors.length)throw new Error(errors.join('\n'));
  console.log('TypeScript/JavaScript primitive-use boundary passed');
 }catch(error){console.error(error.message);process.exitCode=1;}
}
