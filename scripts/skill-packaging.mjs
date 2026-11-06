#!/usr/bin/env node
// One reviewed shipping list for npm skills, Codex copies, and Claude.ai ZIPs.
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const names = JSON.parse(readFileSync(new URL('../skills/shipped.json', import.meta.url), 'utf8'));
if (!Array.isArray(names) || !names.length || new Set(names).size !== names.length ||
    names.some(name => typeof name !== 'string' || !/^aweb-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name))) {
  throw new Error('skills/shipped.json must contain unique aweb skill names');
}
for (const name of names) {
  if (!existsSync(resolve(root, 'skills', name, 'SKILL.md'))) {
    throw new Error(`missing shipped skill source: ${name}/SKILL.md`);
  }
}

const [command, target, ...extra] = process.argv.slice(2);
if (extra.length || !['list', 'sync', 'check-zips'].includes(command) ||
    (command === 'list' ? target !== undefined : !target)) {
  throw new Error('usage: skill-packaging.mjs list | sync DIRECTORY | check-zips DIRECTORY');
}
if (command === 'list') {
  console.log(names.join('\n'));
} else if (command === 'sync') {
  const destination = resolve(target);
  rmSync(destination, { recursive: true, force: true });
  mkdirSync(destination, { recursive: true });
  for (const name of names) cpSync(resolve(root, 'skills', name), resolve(destination, name), { recursive: true });
  console.log(`Synced ${names.length} shipped skills into ${target}`);
} else {
  const expected = names.map(name => `${name}.zip`).sort();
  const actual = readdirSync(target, { withFileTypes: true })
    .filter(entry => entry.isFile() && entry.name.endsWith('.zip')).map(entry => entry.name).sort();
  const missing = expected.filter(name => !actual.includes(name));
  const unexpected = actual.filter(name => !expected.includes(name));
  if (missing.length || unexpected.length) {
    throw new Error(`ZIP set differs from skills/shipped.json; missing: ${missing.join(', ') || 'none'}; unexpected: ${unexpected.join(', ') || 'none'}`);
  }
  console.log(`ZIP names match all ${names.length} shipped skills`);
}
