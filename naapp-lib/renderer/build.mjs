import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
const output = await build({ entryPoints: ['index.mjs'], bundle: true, format: 'esm', target: ['es2022'], legalComments: 'inline', write: false, minify: false });
const destination = '../src/aweb_naapp/pages/assets/page-renderer.js';
const bytes = output.outputFiles[0].text;
if (process.argv.includes('--check')) {
  if (await readFile(destination, 'utf8') !== bytes) throw Error('Renderer bundle is stale; npm run build');
} else await writeFile(destination, bytes);
