import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));

// Inspect actual npm artifacts, not a mirror of the source wording.
function pack(relative, inspect) {
  const destination = mkdtempSync(join(tmpdir(), 'aweb-skills-pack-'));
  try {
    const [result] = JSON.parse(execFileSync('npm', [
      'pack', '--ignore-scripts', '--json', '--pack-destination', destination,
    ], { cwd: join(root, relative), encoding: 'utf8' }));
    const archive = join(destination, result.filename);
    const manifest = JSON.parse(execFileSync('tar', ['-xOf', archive, 'package/package.json'], { encoding: 'utf8' }));
    inspect(manifest, result.files.map(file => file.path));
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
}

test('Pi runtime installs without skill discovery or a skills dependency', () => {
  pack('pi-extension', (manifest, files) => {
    assert.deepEqual(manifest.pi.skills, []);
    assert.deepEqual(manifest.pi.extensions, ['./dist/index.js']);
    assert.ok(files.includes('dist/index.js'), 'build the runtime before testing its artifact');
    assert.ok(!files.some(path => path.startsWith('skills/')));
    assert.ok(!Object.keys(manifest.dependencies).some(name => name.includes('skills')));
  });
});

test('the optional skills artifact exposes every canonical skill to Pi', () => {
  execFileSync('npm', ['run', 'sync-skills'], { cwd: join(root, 'pi-extension') });
  pack('packages/claude-skills', (manifest, files) => {
    assert.deepEqual(manifest.pi.skills, ['./skills']);
    const shipped = JSON.parse(readFileSync(join(root, 'skills/shipped.json'), 'utf8'));
    const actual = [...new Set(files.filter(path => path.startsWith('skills/')).map(path => path.split('/')[1]))].sort();
    assert.deepEqual(actual, [...shipped].sort());
    for (const name of shipped) assert.ok(files.includes(`skills/${name}/SKILL.md`));
    assert.equal(manifest.pi.extensions, undefined);
  });
});

test('the Claude channel artifact has no automatically discovered configure skill', () => {
  pack('channel', (_manifest, files) => {
    assert.ok(!files.some(path => path.startsWith('skills/')));
  });
});
