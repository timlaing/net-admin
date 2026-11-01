/* Progressive subnet editor. The server and agent validate every submitted change. */
const optionLabels = {
  routers: 'Router / gateway',
  'domain-name-servers': 'DNS servers',
  'domain-name': 'Domain name',
  'ntp-servers': 'Time servers (NTP)',
};

function textValue(name, value, backend) {
  if (name !== 'domain-name' || backend !== 'isc') return value;
  if (!value.startsWith('"')) return value;
  // Preserve unusual daemon escape syntax in the original text editor.
  const decoded = JSON.parse(value);
  if (typeof decoded !== 'string') throw new Error('Unsupported domain name format.');
  return decoded;
}

export function parseDraft(ranges, options, backend) {
  const pools = ranges.split('\n').filter(line => line.trim()).map(line => {
    const parts = line.split('-');
    if (parts.length !== 2) throw new Error('Edit the pool text below to correct its format.');
    return { start: parts[0].trim(), end: parts[1].trim() };
  });
  const entries = options.split('\n').filter(line => line.trim()).map(line => {
    const split = line.indexOf('=');
    if (split < 1) throw new Error('Edit the option text below to correct its format.');
    const name = line.slice(0, split).trim();
    const value = line.slice(split + 1).trim();
    return { name, value: String(textValue(name, value, backend)) };
  });
  return { pools, options: entries };
}

export function serializeDraft(draft, backend) {
  return {
    ranges: draft.pools.map(pool => `${pool.start.trim()}-${pool.end.trim()}`).join('\n'),
    options: draft.options.map(option => {
      const name = option.name.trim(), value = option.value.trim();
      const encoded = name === 'domain-name' && backend === 'isc' ? JSON.stringify(value) : value;
      return `${name}=${encoded}`;
    }).join('\n'),
  };
}

function ipv4(value) {
  const parts = value.trim().split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return NaN;
  return parts.reduce((address, part) => address * 256 + Number(part), 0);
}

function validatePools(draft, network, netmask) {
  const first = ipv4(network), last = first + (4294967295 - ipv4(netmask));
  const intervals = [];
  for (let index = 0; index < draft.pools.length; index++) {
    const pool = draft.pools[index], start = ipv4(pool.start), end = ipv4(pool.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start <= first || end >= last) {
      return { kind: 'pool', index, message: `Pool ${index + 1}: enter an ordered address range inside this subnet, excluding its network and broadcast addresses.` };
    }
    if (intervals.some(([left, right]) => start <= right && end >= left)) {
      return { kind: 'pool', index, message: `Pool ${index + 1} overlaps another pool.` };
    }
    intervals.push([start, end]);
  }
  return null;
}

function validateOptions(draft) {
  const names = new Set();
  for (let index = 0; index < draft.options.length; index++) {
    const option = draft.options[index], name = option.name.trim();
    if (!name || !option.value.trim() || /[=\r\n]/.test(name) || /[\r\n]/.test(option.value)) {
      return { kind: 'option', index, message: `Option ${index + 1}: enter a name and value on one line.` };
    }
    if (names.has(name)) return { kind: 'option', index, message: `Duplicate option: ${name}. Combine multiple addresses in one value.` };
    names.add(name);
  }
  return null;
}

export function validateDraft(draft, network, netmask) {
  return validatePools(draft, network, netmask) || validateOptions(draft);
}

export function draftChanges(before, after) {
  const changes = [];
  const poolText = pool => `${pool.start} – ${pool.end}`;
  const oldPools = before.pools.map(poolText), newPools = after.pools.map(poolText);
  oldPools.filter(pool => !newPools.includes(pool)).forEach(pool => changes.push(`Remove pool ${pool}`));
  newPools.filter(pool => !oldPools.includes(pool)).forEach(pool => changes.push(`Add pool ${pool}`));
  const oldOptions = new Map(before.options.map(option => [option.name, option.value]));
  const newOptions = new Map(after.options.map(option => [option.name, option.value]));
  for (const [name, value] of oldOptions) {
    const label = optionLabels[name] || name;
    if (!newOptions.has(name)) changes.push(`Remove ${label}: ${value}. Inherited defaults will apply, if configured.`);
    else if (newOptions.get(name) !== value) changes.push(`Change ${label}: ${value} → ${newOptions.get(name)}`);
  }
  for (const [name, value] of newOptions) {
    if (!oldOptions.has(name)) changes.push(`Add ${optionLabels[name] || name}: ${value}`);
  }
  return changes;
}

class SubnetEditor {
  constructor(form) {
    this.form = form;
    this.backend = form.dataset.backend;
    this.sequence = 0;
    this.poolRows = [];
    this.optionRows = [];
    this.reviewed = null;
    const ranges = JSON.parse(form.dataset.baselineRanges).map(pair => pair.join('-')).join('\n');
    const options = Object.entries(JSON.parse(form.dataset.baselineOptions)).map(([name, value]) => `${name}=${value}`).join('\n');
    this.baseline = parseDraft(ranges, options, this.backend);
    const draft = parseDraft(form.elements.ranges.value, form.elements.options.value, this.backend);
    draft.pools.forEach(pool => this.addPool(pool));
    draft.options.forEach(option => this.addOption(option));
    this.find('[data-add-pool]').addEventListener('click', () => this.addPool());
    this.find('[data-add-option]').addEventListener('click', () => this.addOption());
    this.find('[data-keep-editing]').addEventListener('click', () => {
      this.find('[data-subnet-review]').hidden = true;
      this.find('[data-review-subnet]').focus();
    });
    form.addEventListener('submit', event => this.submit(event));
    form.addEventListener('input', () => this.changed());
    form.addEventListener('change', () => this.changed());
    // Hide the text fallback only after every row has been constructed successfully.
    this.find('[data-subnet-fallback]').hidden = true;
    this.find('[data-subnet-controls]').hidden = false;
    this.changed();
  }

  find(selector) { return this.form.querySelector(selector); }

  field(label, value = '') {
    const wrapper = document.createElement('div');
    const heading = document.createElement('label');
    const input = document.createElement('input');
    input.id = `subnet-field-${++this.sequence}`;
    heading.htmlFor = input.id;
    heading.className = 'form-label';
    heading.textContent = label;
    input.className = 'form-control';
    input.value = value;
    input.required = true;
    input.autocomplete = 'off';
    wrapper.append(heading, input);
    return { wrapper, input };
  }

  row(kind, description) {
    const wrapper = document.createElement('div');
    wrapper.className = 'subnet-editor-row';
    const fields = document.createElement('div');
    fields.className = 'subnet-editor-fields';
    const removed = document.createElement('div');
    removed.className = 'subnet-removed';
    removed.hidden = true;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'btn btn-outline-danger';
    remove.textContent = 'Remove';
    remove.setAttribute('aria-label', `Remove ${description}`);
    const undo = document.createElement('button');
    undo.type = 'button';
    undo.className = 'btn btn-outline-secondary';
    undo.textContent = 'Undo';
    const message = document.createElement('span');
    message.textContent = `${description} removed`;
    removed.append(message, undo);
    const row = { wrapper, fields, remove, removed, active: true };
    remove.addEventListener('click', () => this.toggleRow(row, false));
    undo.addEventListener('click', () => this.toggleRow(row, true));
    wrapper.append(fields, removed);
    this.find(`[data-${kind}-rows]`).append(wrapper);
    return row;
  }

  toggleRow(row, active) {
    row.active = active;
    row.fields.hidden = !active;
    row.removed.hidden = active;
    row.fields.querySelectorAll('input, select').forEach(input => { input.disabled = !active; });
    if (active && row.custom) row.custom.input.disabled = row.select.value !== 'custom';
    this.changed();
    if (active) row.fields.querySelector('input, select').focus();
    else row.removed.querySelector('button').focus();
  }

  addPool(pool) {
    const row = this.row('pool', pool ? `pool ${pool.start} – ${pool.end}` : 'new pool');
    row.start = this.field('Start address', pool?.start);
    row.end = this.field('End address', pool?.end);
    row.fields.append(row.start.wrapper, row.end.wrapper, row.remove);
    this.poolRows.push(row);
    if (!pool) { this.changed(); row.start.input.focus(); }
  }

  addOption(option) {
    const row = this.row('option', option ? `option ${optionLabels[option.name] || option.name}` : 'new option');
    const choice = document.createElement('div');
    const label = document.createElement('label');
    label.className = 'form-label';
    label.textContent = 'Option';
    row.select = document.createElement('select');
    row.select.id = `subnet-field-${++this.sequence}`;
    label.htmlFor = row.select.id;
    row.select.className = 'form-select';
    row.select.required = true;
    const choices = { '': 'Choose an option', ...optionLabels, custom: 'Custom option…' };
    Object.entries(choices).forEach(([value, text]) => row.select.add(new Option(text, value)));
    row.select.value = option ? (Object.hasOwn(optionLabels, option.name) ? option.name : 'custom') : '';
    row.custom = this.field('Custom option name', option?.name);
    choice.append(label, row.select, row.custom.wrapper);
    row.value = this.field('Value', option?.value);
    const hint = document.createElement('p');
    hint.className = 'form-text mb-0';
    hint.id = `${row.value.input.id}-hint`;
    row.value.input.setAttribute('aria-describedby', hint.id);
    row.value.wrapper.append(hint);
    row.hint = hint;
    row.select.addEventListener('change', () => this.optionKind(row));
    row.fields.append(choice, row.value.wrapper, row.remove);
    this.optionRows.push(row);
    this.optionKind(row);
    if (!option) { this.changed(); row.select.focus(); }
  }

  optionKind(row) {
    const kind = row.select.value;
    row.custom.wrapper.hidden = kind !== 'custom';
    row.custom.input.disabled = kind !== 'custom';
    let hint = 'Use a comma-separated list for multiple addresses.';
    if (kind === 'domain-name') hint = 'Enter the domain without quotes; formatting is handled automatically.';
    if (kind === 'custom') hint = `Use ${this.backend.toUpperCase()} option syntax${this.backend === 'isc' ? '; quote text values' : ''}.`;
    if (!kind) hint = 'Choose a common setting or a custom option.';
    row.hint.textContent = hint;
  }

  draft() {
    return {
      pools: this.poolRows.filter(row => row.active).map(row => ({ start: row.start.input.value.trim(), end: row.end.input.value.trim() })),
      options: this.optionRows.filter(row => row.active).map(row => ({ name: (row.select.value === 'custom' ? row.custom.input.value : row.select.value).trim(), value: row.value.input.value.trim() })),
    };
  }

  changed() {
    const draft = this.draft(), serialized = serializeDraft(draft, this.backend);
    this.form.elements.ranges.value = serialized.ranges;
    this.form.elements.options.value = serialized.options;
    this.reviewed = null;
    this.find('[data-subnet-review]').hidden = true;
    this.find('[data-draft-error]').textContent = '';
    this.find('[data-draft-status]').textContent = draftChanges(this.baseline, draft).length ? 'Unsaved changes' : 'No pending changes';
    this.find('[data-pool-count]').textContent = draft.pools.length;
    this.find('[data-option-count]').textContent = draft.options.length;
    this.find('[data-pools-empty]').hidden = draft.pools.length > 0;
    this.find('[data-options-empty]').hidden = draft.options.length > 0;
    this.form.querySelectorAll('[aria-invalid]').forEach(input => input.removeAttribute('aria-invalid'));
  }

  submit(event) {
    const draft = this.draft(), serialized = serializeDraft(draft, this.backend);
    const snapshot = JSON.stringify(serialized);
    if (event.submitter?.matches('[data-apply-subnet]') && this.reviewed === snapshot) return;
    event.preventDefault();
    const error = validateDraft(draft, this.form.dataset.network, this.form.dataset.netmask);
    if (error) {
      this.find('[data-draft-error]').textContent = error.message;
      const rows = error.kind === 'pool' ? this.poolRows : this.optionRows;
      const row = rows.filter(item => item.active)[error.index];
      row.fields.querySelectorAll('input:not(:disabled), select').forEach(input => input.setAttribute('aria-invalid', 'true'));
      row.fields.querySelector('input:not(:disabled), select').focus();
      return;
    }
    const changes = draftChanges(this.baseline, draft);
    if (!changes.length) { this.find('[data-draft-error]').textContent = 'There are no pending changes.'; return; }
    const summary = this.find('[data-subnet-summary]');
    summary.replaceChildren();
    changes.forEach(change => { const item = document.createElement('li'); item.textContent = change; summary.append(item); });
    this.form.elements.ranges.value = serialized.ranges;
    this.form.elements.options.value = serialized.options;
    this.reviewed = snapshot;
    this.find('[data-draft-error]').textContent = '';
    this.find('[data-subnet-review]').hidden = false;
    this.find('[data-apply-subnet]').focus();
  }
}

if (typeof document !== 'undefined') {
  document.querySelectorAll('[data-subnet-editor]').forEach(form => {
    try { new SubnetEditor(form); } catch (_) { /* Keep the original fields available for unusual input. */ }
  });
}
