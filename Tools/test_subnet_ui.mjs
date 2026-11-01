// Validate the production editor's draft conversion, validation and review content.
import assert from 'node:assert/strict';
import { parseDraft, serializeDraft, validateDraft, draftChanges } from '../netadmin/static/subnet-editor.js';
const network = '192.0.2.0', mask = '255.255.255.0';
const original = parseDraft('192.0.2.10-192.0.2.20\n192.0.2.40-192.0.2.50',
  'domain-name="example.net"\nrouters=192.0.2.1\ncustom-option="a=b"', 'isc');
assert.equal(original.options[0].value, 'example.net');
assert.equal(serializeDraft(original, 'isc').options,
  'domain-name="example.net"\nrouters=192.0.2.1\ncustom-option="a=b"');
assert.equal(validateDraft(original, network, mask), null);
assert.deepEqual(draftChanges(original, structuredClone(original)), []);
const changed = structuredClone(original);
changed.pools.splice(0, 1);
changed.pools.push({ start: '192.0.2.100', end: '192.0.2.120' });
changed.options[0].value = 'new.example.net';
changed.options.splice(1, 1);
const review = draftChanges(original, changed).join('\n');
assert.match(review, /Remove pool 192\.0\.2\.10 – 192\.0\.2\.20/);
assert.match(review, /Add pool 192\.0\.2\.100 – 192\.0\.2\.120/);
assert.match(review, /example\.net → new\.example\.net/);
assert.match(review, /Remove Router \/ gateway.*Inherited defaults/);
assert.equal(serializeDraft(changed, 'isc').options.includes('domain-name="new.example.net"'), true);
const empty = { pools: [], options: [] };
assert.deepEqual(serializeDraft(empty, 'isc'), { ranges: '', options: '' });
assert.equal(validateDraft(empty, network, mask), null);
assert.equal(draftChanges(original, empty).length, 5);
for (const range of ['192.0.2.0-192.0.2.10', '192.0.2.250-192.0.2.255',
  '198.51.100.10-198.51.100.20', '192.0.2.30-192.0.2.20', 'not-an-address-192.0.2.20',
  '192.0.2.10-192.0.2.20\n192.0.2.20-192.0.2.30']) {
  const pools = range.split('\n').map(text => { const parts = text.split('-'); return { start: parts[0], end: parts.slice(1).join('-') }; });
  assert.equal(validateDraft({ pools, options: [] }, network, mask).kind, 'pool');
}
for (const options of [[{ name: '', value: 'x' }], [{ name: 'routers', value: '' }],
  [{ name: 'routers', value: 'a' }, { name: 'routers', value: 'b' }],
  [{ name: 'custom\noption', value: 'x' }]]) {
  assert.equal(validateDraft({ pools: [], options }, network, mask).kind, 'option');
}
const kea = parseDraft('', 'domain-name=example.net', 'kea');
assert.equal(serializeDraft(kea, 'kea').options, 'domain-name=example.net');
assert.throws(() => parseDraft('invalid', '', 'isc'));
assert.throws(() => parseDraft('', 'missing separator', 'isc'));
assert.throws(() => parseDraft('', 'domain-name="bad\\escape"', 'isc'));
console.log('Subnet draft round trips, quotes, removals, review details and validation passed');
