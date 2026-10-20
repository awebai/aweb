import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const schema = JSON.parse(readFileSync(new URL('../../src/aweb_naapp/pages/page-format-v1.schema.json', import.meta.url)));

test('tag and CSS token inputs remain closed and bounded by the frozen schema', () => {
  const props = name => schema.$defs[`widget_${name}`].properties.props.properties;
  assert.equal(props('heading').level.type, 'integer');
  assert.equal(props('heading').level.minimum, 1);
  assert.equal(props('heading').level.maximum, 6);
  assert.deepEqual(props('stack').gap.enum, ['small', 'medium', 'large']);
  assert.deepEqual(props('status_badge').tone.enum, ['neutral', 'info', 'success', 'warning', 'danger']);
  assert.equal(props('grid').columns.type, 'integer');
  assert.equal(props('grid').columns.maximum, 4);
});
