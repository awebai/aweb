#!/usr/bin/env node
// Raw primitive boundary for TypeScript and JavaScript; no call-count catalog.
// It does not attempt reflection or whole-program data-flow analysis.
import { createRequire } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(path.join(defaultRoot,'channel-core/package.json'));
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
const normalized=name=>name.replace(/^(?:reference:|module-literal:)/,'').replace(/^(?:globalThis|self|window)\.crypto(?=\.|$)/,'crypto');
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
 const record=(scope,callee)=>{const symbol=scope.join('.')||'<module>';result[symbol]??={};result[symbol][callee]=true;};
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
  if(!file || !extensions.test(file) || excluded(file) || !existsSync(path.join(root,file)))continue;
  let parsed;try{parsed=scanSource(readFileSync(path.join(root,file),'utf8'),file);}catch(error){throw new Error(`cannot scan ${file}: ${error.message}`);}
  for(const [symbol,calls] of Object.entries(parsed))sites.push({file,symbol,calls});
 }
 return sites;
}

export function checkPrimitiveUses(observed,legacy) {
 const errors=[];const files=new Set();
 for(const entry of legacy) {
  if(!entry.file || typeof entry.reason!=='string' || !entry.reason.trim())errors.push('legacy primitive file requires a reason');
  else files.add(entry.file);
 }
 for(const entry of observed)for(const callee of Object.keys(entry.calls)) {
  if(!rawUse(callee))continue;
  const codec=entry.file==='channel-core/src/identity/id_certificates.ts';
  const name=normalized(callee);
  if(codec && entry.symbol==='idEd25519Verify')continue;
  if(entry.file==='channel-core/src/identity/did.ts' && entry.symbol==='primeSubgroupPoint')continue;
  if(codec && entry.symbol==='<module>' && ['@noble/ed25519.etc.sha512Sync','@noble/ed25519.etc.concatBytes','@noble/ed25519.CURVE.n'].includes(name))continue;
  if(files.has(entry.file))continue;
  errors.push(`raw TS crypto must use the shared verifier: ${entry.file}:${entry.symbol}: ${callee}`);
 }
 return errors;
}

export function checkInventory(root) {
 const inventory=JSON.parse(readFileSync(path.join(root,'docs/identity-tree-coverage.json'),'utf8'));
 return checkPrimitiveUses(scanRepository(root),inventory.primitive_guard.legacy_files);
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 try {
  if(process.argv.length!==2)throw new Error('usage: check_identity_ts_inventory.mjs');
  const errors=checkInventory(defaultRoot);if(errors.length)throw new Error(errors.join('\n'));
  console.log('TypeScript/JavaScript primitive-use boundary passed');
 }catch(error){console.error(error.message);process.exitCode=1;}
}
