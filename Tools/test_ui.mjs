// Exercise pagination and mode toggling with the production script and a minimal DOM.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
class Element {
  constructor(value = '') { this.value = value; this.listeners = {}; this.hidden = false; }
  addEventListener(event, callback) { this.listeners[event] = callback; }
  fire(event) { this.listeners[event]?.(); }
}
function fixture(id, count) {
  const rows = Array.from({ length: count }, (_, i) => ({ textContent: `device-${i} ${i % 2 ? 'odd' : 'even'}` }));
  const size = new Element('25'), previous = new Element(), next = new Element(), position = new Element(), counter = new Element();
  const tools = { querySelector: selector => ({ '[data-page-size]': size, '[data-page-previous]': previous, '[data-page-next]': next, '[data-page-position]': position })[selector] };
  const input = new Element(); input.dataset = { tableFilter: id }; input.closest = () => tools;
  return { input, size, previous, next, position, counter, rows,
    table: { id, querySelectorAll: () => rows }, visible: () => rows.filter(row => !row.hidden) };
}
const leases = fixture('leases', 273), clients = fixture('clients', 4);
const mode = new Element(); mode.checked = true;
const direct = new Element(), agentField = new Element();
let polling = [], fetchCalls = 0, connected = true;
function statusCard(url) {
  const badge = new Element(), message = new Element(), checked = new Element();
  const classes = new Set();
  badge.classList = { toggle(name, on) { on ? classes.add(name) : classes.delete(name); },
    add(name) { classes.add(name); }, remove(name) { classes.delete(name); } };
  return { dataset: { connectionStatusUrl: url }, badge, message, checked, classes,
    querySelector: selector => ({ '[data-connection-state]': badge, '[data-connection-message]': message, '[data-connection-checked]': checked })[selector] };
}
const status = statusCard('/connections/status/dhcp');
const document = {
  documentElement: { dataset: {} },
  getElementById: id => ({ dns_use_agent: mode, leases: leases.table, clients: clients.table })[id],
  addEventListener: (_, callback) => callback(),
  querySelector: selector => selector.includes('leases') ? leases.counter : clients.counter,
  querySelectorAll: selector => ({ '[data-direct-dns]': [direct], '[data-dns-agent-field]': [agentField], '[data-table-filter]': [leases.input, clients.input], '[data-connection-status-url]': [status] })[selector] || [],
};
vm.runInNewContext(readFileSync(new URL('../netadmin/static/app.js', import.meta.url), 'utf8'), {
  document, window: { matchMedia: () => ({ matches: false, addEventListener() {} }), setInterval(callback, delay) { assert.equal(delay, 30000); polling.push(callback); } },
  AbortSignal, fetch: async (url, options) => { fetchCalls++; assert.equal(url, '/connections/status/dhcp'); assert.equal(options.credentials, 'same-origin'); if (!connected) throw new Error('private backend data'); return { ok: true, redirected: false, json: async () => ({ state: 'Connected', message: 'Agent authenticated', checked_at: 1 }) }; },
  localStorage: { getItem: () => null }, ResizeObserver: class { observe() {} },
});
assert.equal(leases.visible().length, 25);
assert.equal(leases.position.textContent, 'Page 1 of 11');
assert.equal(leases.previous.disabled, true);
leases.next.fire('click');
assert.equal(leases.visible()[0].textContent, 'device-25 odd');
assert.equal(clients.visible().length, 4); // Tables have independent pages.
leases.input.value = 'odd'; leases.input.fire('input');
assert.equal(leases.visible().length, 25);
assert.equal(leases.position.textContent, 'Page 1 of 6');
leases.size.value = '100'; leases.size.fire('change');
assert.equal(leases.visible().length, 100);
leases.next.fire('click');
assert.equal(leases.visible().length, 36);
assert.equal(leases.next.disabled, true);
leases.previous.fire('click');
assert.equal(leases.visible().length, 100);
leases.input.value = 'no matches'; leases.input.fire('input');
assert.equal(leases.visible().length, 0);
assert.equal(leases.next.disabled, true);
assert.equal(leases.previous.disabled, true);
assert.equal(direct.hidden, true);
mode.checked = false; mode.fire('change');
assert.equal(direct.hidden, false);
assert.equal(direct.open, true);
assert.equal(agentField.hidden, true);
mode.checked = true; mode.fire('change');
assert.equal(direct.hidden, true);
assert.equal(agentField.hidden, false);
console.log('Pagination, search, page-size, independent tables and direct DNS mode passed');

await new Promise(setImmediate);
assert.equal(status.badge.textContent, 'Connected');
assert.equal(status.classes.has('status-success'), true);
connected = false;
await polling[0]();
assert.equal(status.badge.textContent, 'Unavailable');
assert.equal(status.classes.has('status-success'), false);
assert.equal(status.classes.has('status-warning'), true);
assert.equal(status.message.textContent.includes('private backend data'), false);
document.hidden = true;
const before = fetchCalls;
await polling[0]();
assert.equal(fetchCalls, before);
console.log('Overview status refresh, failure state and hidden-page pause passed');
