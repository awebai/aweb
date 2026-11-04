import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const source = fileURLToPath(new URL('../', import.meta.url));
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'aweb-skill-packaging-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const path of ['skills/shipped.json', 'scripts/skill-packaging.mjs',
    'packages/claude-ai-skills/build-zips.sh', 'packages/claude-skills/package.json',
    'packages/codex-plugin/sync-skills.sh', 'pi-extension/package.json']) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    cpSync(join(source, path), join(root, path));
  }
  const names = JSON.parse(readFileSync(join(root, 'skills/shipped.json'), 'utf8'));
  for (const name of names) addSource(root, name);
  return { root, names, dist: join(root, 'packages/claude-ai-skills/dist') };
}
function addSource(root, name) {
  mkdirSync(join(root, 'skills', name), { recursive: true });
  writeFileSync(join(root, 'skills', name, 'SKILL.md'), `# ${name}\n`);
}
function build(root) {
  execFileSync('bash', ['packages/claude-ai-skills/build-zips.sh'], { cwd: root });
}
function check(root, dist) {
  return spawnSync(process.execPath, ['scripts/skill-packaging.mjs', 'check-zips', dist], { cwd: root, encoding: 'utf8' });
}

test('ZIP gate accepts shipped names and rejects a same-count substitution', t => {
  const { root, names, dist } = fixture(t);
  build(root);
  assert.equal(check(root, dist).status, 0);
  renameSync(join(dist, `${names[0]}.zip`), join(dist, 'aweb-wrong.zip'));
  const result = check(root, dist);
  assert.notEqual(result.status, 0);
  assert.ok(result.stderr.includes(`${names[0]}.zip`));
  assert.match(result.stderr, /unexpected: aweb-wrong.zip/);
});

test('ZIP gate rejects missing and extra archives', t => {
  const { root, names, dist } = fixture(t);
  build(root);
  const archive = join(dist, `${names[0]}.zip`);
  const bytes = readFileSync(archive);
  rmSync(archive);
  assert.notEqual(check(root, dist).status, 0);
  writeFileSync(archive, bytes);
  writeFileSync(join(dist, 'unexpected.zip'), bytes);
  assert.notEqual(check(root, dist).status, 0);
});

test('one shipping-list addition reaches ZIPs, Claude, Codex and Pi sync', t => {
  const { root, names, dist } = fixture(t);
  const added = 'aweb-future-fixture';
  names.push(added);
  addSource(root, added);
  writeFileSync(join(root, 'skills/shipped.json'), JSON.stringify(names));
  build(root);
  assert.equal(check(root, dist).status, 0);
  for (const cwd of ['packages/claude-skills', 'packages/codex-plugin', 'pi-extension']) {
    if (cwd === 'packages/codex-plugin') execFileSync('bash', ['sync-skills.sh'], { cwd: join(root, cwd) });
    else execFileSync('npm', ['run', 'sync-skills'], { cwd: join(root, cwd) });
    const destination = cwd === 'pi-extension' ? 'packages/claude-skills' : cwd;
    assert.equal(readFileSync(join(root, destination, 'skills', added, 'SKILL.md'), 'utf8'), `# ${added}\n`);
    // Force the Pi wrapper to recreate the optional package instead of passing on a stale copy.
    rmSync(join(root, destination, 'skills'), { recursive: true });
  }
});
