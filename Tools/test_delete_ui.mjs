// Exercise the shared production deletion controller without live services.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

class Element {
  constructor() { this.listeners = {}; this.dataset = {}; this.attributes = {}; this.hidden = false; this.disabled = false; this.checked = false; this.children = []; this.textContent = ''; }
  addEventListener(name, callback) { (this.listeners[name] ??= []).push(callback); }
  dispatchEvent(event) { this.fire(event.type); }
  fire(name) { const event = { preventDefault() { this.prevented = true; } }; this.listeners[name]?.forEach(callback => callback(event)); return event; }
  setAttribute(name, value) {
    this.attributes[name] = value;
    if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase())] = value;
    if (name === 'hidden') this.hidden = true;
  }
  hasAttribute(name) { return name in this.attributes; }
  append(...children) { this.children.push(...children); }
  focus(options) { this.focusOptions = options; }
}
const tick = () => new Promise(setImmediate);
const paths = ['/dns/records/delete', '/dhcp/reservations/delete', '/dhcp/subnets/delete', '/radius/users/delete', '/radius/clients/delete'];
const standalonePaths = ['/dns/zones/delete', '/dhcp/subnets/delete', '/certificates/authorities/delete'];
function fixture(path = paths[0], behavior = async () => ({ ok: true, json: async () => ({ deleted: true, refresh_url: '/list' }) })) {
  const table = new Element(); table.id = 'items';
  const other = new Element(); other.id = 'other'; other.querySelectorAll = () => [];
  const header = new Element(), count = new Element(), empty = new Element(), filter = new Element();
  const selected = new Element(), clear = new Element(), selectedCount = new Element(), message = new Element();
  const tools = new Element(); tools.hidden = true;
  tools.querySelector = selector => ({ '[data-delete-selected]': selected, '[data-delete-clear]': clear, '[data-delete-selected-count]': selectedCount, '[data-delete-message]': message })[selector];
  let rows = [], calls = [], confirmations = [], agree = true, scroll = null, history = null;
  const cells = [new Element()];
  function row(index, { hidden = false, protectedRow = false } = {}) {
    const result = new Element(); result.hidden = hidden;
    const box = new Element(), button = new Element(), form = new Element();
    form.action = `https://netadmin.test/api/hassio_ingress/test${path}`;
    form.dataset.confirm = `Delete item-${index}?`;
    form.fields = { csrf_token: 'synthetic-csrf', name: `item-${index}`, value: `192.0.2.${index}` };
    form.closest = selector => selector === 'tr' ? result : table;
    form.querySelectorAll = () => [button];
    box.closest = () => result;
    result.box = protectedRow ? null : box; result.form = protectedRow ? null : form; result.button = button;
    result.querySelector = () => result.form;
    result.remove = () => { rows = rows.filter(value => value !== result); };
    rows.push(result); return result;
  }
  row(1); row(2); row(3, { hidden: true }); row(4, { protectedRow: true });
  const forms = () => rows.flatMap(row => row.form ? [row.form] : []);
  const boxes = () => rows.flatMap(row => row.box ? [row.box] : []);
  table.querySelector = () => header;
  table.closest = () => null;
  table.querySelectorAll = selector => ({ '[data-row-delete]': forms(), '[data-delete-row]': boxes(), '[data-filter-row]': rows,
    '[data-delete-selection]': cells, '[data-row-delete] button, [data-delete-row]': rows.flatMap(row => row.box ? [row.box, row.button] : []) })[selector] || [];
  const main = new Element(); main.replaceChildren = (...children) => { main.children = children; };
  const standalone = new Element(); standalone.action = `https://netadmin.test${standalonePaths[0]}`;
  standalone.dataset.confirm = 'Delete entire zone?'; standalone.fields = { csrf_token: 'synthetic-csrf', zone: 'example.test' };
  standalone.closest = () => null;
  standalone.querySelectorAll = () => [new Element()];
  const document = new Element();
  document.createElement = () => new Element();
  document.getElementById = id => ({ 'filter-items': filter, 'main-content': main })[id];
  document.querySelectorAll = selector => ({ 'table': [table, other], 'form[action]': [...forms(), standalone], 'form[data-async-delete]': [standalone] })[selector] || [];
  document.querySelector = selector => selector.startsWith('[data-record-delete-tools') ? tools : selector.startsWith('[data-record-count') ? count : empty;
  const window = { location: { href: 'https://netadmin.test/list', origin: 'https://netadmin.test' }, scrollX: 0, scrollY: 200,
    confirm: text => { confirmations.push(text); return agree; }, scrollTo: (x, y) => { scroll = [x, y]; }, history: { replaceState: (_state, _title, url) => { history = url; } } };
  vm.runInNewContext(readFileSync(new URL('../netadmin/static/table_delete.js', import.meta.url), 'utf8'), {
    document, window, Event, URL, AbortSignal,
    FormData: class { constructor(form) { this.fields = { ...form.fields }; } },
    DOMParser: class { parseFromString() { return { getElementById: () => ({ childNodes: ['fresh-state'] }) }; } },
    fetch: async (url, options) => { calls.push({ url, options }); return behavior(url, options, calls.length); },
  });
  document.fire('DOMContentLoaded');
  return { table, tools, header, selected, clear, selectedCount, count, empty, message, filter, main, standalone, document,
    rows: () => rows, calls, confirmations, cancel: () => { agree = false; }, scroll: () => scroll, history: () => history };
}

for (const path of paths) {
  const f = fixture(path);
  assert.equal(f.tools.hidden, false);
  assert.equal(f.selected.disabled, true);
  f.header.checked = true; f.header.fire('change');
  assert.deepEqual(f.rows().map(row => row.box?.checked), [true, true, false, undefined]);
  f.rows()[2].box.checked = true; f.rows()[2].box.fire('change');
  assert.match(f.selectedCount.textContent, /3 selected \(1 on other pages/);
  f.clear.fire('click');
  assert.equal(f.selected.disabled, true);
  const target = f.rows()[0];
  assert.equal(target.form.fire('submit').prevented, true);
  target.form.fire('submit'); // An in-flight request must never be duplicated.
  assert.equal(target.button.disabled, true);
  await tick();
  assert.equal(f.calls.length, 1);
  const { options } = f.calls[0];
  assert.equal(options.method, 'POST');
  assert.equal(options.credentials, 'same-origin');
  assert.equal(options.redirect, 'error');
  assert.equal(options.headers.Accept, 'application/json');
  assert.equal(options.body.fields.csrf_token, 'synthetic-csrf');
  assert.equal(options.body.fields.name, 'item-1');
  assert.equal(f.rows().length, 3);
  assert.equal(f.count.textContent, '3');
  assert.equal(f.filter.focusOptions.preventScroll, true);
  assert.equal(f.confirmations.length, 1);
  f.document.fire('netadmin-content-updated');
  assert.equal(f.rows()[0].form.listeners.submit.length, 1); // Reinitialization is idempotent.
}
console.log('DNS, DHCP and RADIUS row deletion share confirmation, CSRF, explicit ACK and busy guards');

const cancelled = fixture(); cancelled.cancel();
cancelled.rows()[0].form.fire('submit'); await tick();
assert.equal(cancelled.calls.length, 0); assert.equal(cancelled.rows().length, 4);

for (const failure of ['http', 'redirect', 'malformed', 'false', 'network']) {
  const f = fixture(paths[0], async (_url, _options, index) => {
    if (index === 1) return { ok: true, json: async () => ({ deleted: true }) };
    if (failure === 'network') throw new Error('private remote detail');
    return { ok: failure !== 'http', redirected: failure === 'redirect', json: async () => {
      if (failure === 'malformed') throw new Error('private response');
      return { deleted: false };
    } };
  });
  f.rows().forEach(row => { if (row.box) row.box.checked = true; });
  f.selected.fire('click'); await tick();
  assert.equal(f.calls.length, 2); // Stop at the first uncertain result; do not retry or continue.
  assert.equal(f.rows().length, 3);
  assert.match(f.message.textContent, /Deleted 1 of 3 items/);
  assert.match(f.message.textContent, /Refresh to verify/);
  assert.equal(f.message.textContent.includes('private'), false);
  assert.equal(f.rows().filter(row => row.box?.checked).length, 2);
  assert.equal(f.selected.disabled, false);
  assert.match(f.confirmations[0], /other pages or hidden by filters/);
  assert.match(f.confirmations[0], /item-3/);
}
console.log('Bulk partial failures retain uncertain rows/selections, stop safely, and never expose remote data');

const complete = fixture();
complete.rows().forEach(row => { if (row.box) row.box.checked = true; });
complete.selected.fire('click'); await tick();
assert.equal(complete.calls.length, 3);
assert.equal(complete.rows().length, 1); // Protected row is never selected or removed.
assert.equal(complete.selected.disabled, true);

for (const path of standalonePaths) {
  const f = fixture(paths[0], async (_url, options) => options.method === 'POST' ?
    { ok: true, json: async () => ({ deleted: true, refresh_url: '/list' }) } : { ok: true, text: async () => '<main id="main-content">fresh</main>' });
  f.standalone.action = `https://netadmin.test${path}`;
  if (path.includes('authorities')) f.standalone.dataset.deleteTimeout = '110000';
  f.standalone.fire('submit');
  f.rows()[0].form.fire('submit'); // Topology deletion and row deletion cannot overlap.
  await tick();
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[0].options.body.fields.csrf_token, 'synthetic-csrf');
  assert.deepEqual(f.main.children, ['fresh-state']);
  assert.deepEqual(f.scroll(), [0, 200]);
  assert.equal(f.history(), 'https://netadmin.test/list');
}
console.log('Standalone zone, subnet and authority deletion update content in place without page navigation');

const refreshFailure = fixture(paths[0], async (_url, options) => options.method === 'POST' ?
  { ok: true, json: async () => ({ deleted: true, refresh_url: '/list' }) } : { ok: false });
refreshFailure.standalone.fire('submit'); await tick();
assert.match(refreshFailure.standalone.children.at(-1).textContent, /Deletion confirmed, but the view/);
assert.equal(refreshFailure.calls.length, 2);
const authorityFailure = fixture(paths[0], async () => ({ ok: false }));
authorityFailure.standalone.action = 'https://netadmin.test/certificates/authorities/delete';
authorityFailure.standalone.dataset.deleteOperationUrl = '/certificates/authorities/operations/synthetic-original-id';
authorityFailure.standalone.fire('submit'); await tick();
assert.equal(authorityFailure.calls.length, 1);
const recovery = authorityFailure.standalone.children.at(-1).children[0];
assert.equal(recovery.attributes.href, '/certificates/authorities/operations/synthetic-original-id');
assert.equal(recovery.textContent, 'Check original operation');
console.log('Uncertain CA deletion retains its original-operation recovery link without automatic replay');
