/* Progressive enhancement: delete confirmed rows without replacing table state. */
(() => {
  'use strict';
  const enhanced = new WeakSet();
  let activeDelete = false;
  const setActive = value => {
    activeDelete = value;
    document.querySelectorAll('table').forEach(table => { table.dispatchEvent(new Event('deletion-state-changed')); });
  };
  const rowPaths = ['/dns/records/delete', '/dhcp/reservations/delete', '/dhcp/subnets/delete', '/radius/users/delete', '/radius/clients/delete'];
  const standalonePaths = ['/dns/zones/delete', '/dhcp/subnets/delete', '/certificates/authorities/delete'];
  const create = (tag, attributes, text = '') => {
    const element = document.createElement(tag);
    Object.entries(attributes).forEach(([name, value]) => element.setAttribute(name, value));
    element.textContent = text;
    return element;
  };
  const acknowledge = async (form, body) => {
    const response = await fetch(form.action, {
      method: 'POST', body, headers: { Accept: 'application/json' }, credentials: 'same-origin',
      redirect: 'error', signal: AbortSignal.timeout(Number(form.dataset.deleteTimeout) || 30000),
    });
    if (!response.ok || response.redirected) throw new Error('Deletion not acknowledged');
    const result = await response.json();
    if (result.deleted !== true) throw new Error('Deletion not acknowledged');
    return result;
  };
  const refreshContent = async destination => {
    const url = new URL(destination, window.location.href);
    if (url.origin !== window.location.origin) throw new Error('Invalid refresh destination');
    const states = [...document.querySelectorAll('[data-table-filter]')].map(input => {
      const table = document.getElementById(input.dataset.tableFilter);
      const headers = [...(table.tHead?.rows[0].cells || [])];
      const sorted = headers.findIndex(header => ['ascending', 'descending'].includes(header.getAttribute('aria-sort')));
      return { id: table.id, query: input.value, size: input.closest('[data-filter-tools]').querySelector('[data-page-size]').value,
        page: table.dataset.page, sorted, direction: headers[sorted]?.getAttribute('aria-sort') };
    });
    const response = await fetch(url.href, { credentials: 'same-origin', redirect: 'error', signal: AbortSignal.timeout(30000) });
    if (!response.ok || response.redirected) throw new Error('View update failed');
    const fresh = new DOMParser().parseFromString(await response.text(), 'text/html').getElementById('main-content');
    if (!fresh) throw new Error('View update failed');
    const x = window.scrollX, y = window.scrollY;
    document.getElementById('main-content').replaceChildren(...fresh.childNodes);
    window.history.replaceState(null, '', url.href);
    document.dispatchEvent(new Event('netadmin-content-updated'));
    states.forEach(state => {
      const table = document.getElementById(state.id);
      const input = document.querySelector(`[data-table-filter="${state.id}"]`);
      if (!table || !input) return;
      const size = input.closest('[data-filter-tools]').querySelector('[data-page-size]');
      input.value = state.query; size.value = state.size;
      input.dispatchEvent(new Event('input')); size.dispatchEvent(new Event('change'));
      if (state.sorted >= 0) {
        const button = table.tHead.rows[0].cells[state.sorted].querySelector('.table-sort');
        button?.click();
        if (state.direction === 'descending') button?.click();
      }
      table.dataset.page = state.page;
      table.dispatchEvent(new Event('table-state-restore'));
    });
    window.scrollTo(x, y);
  };
  const initialize = () => {
    document.querySelectorAll('form[action]').forEach(form => {
      const path = new URL(form.action, window.location.href).pathname;
      if (rowPaths.some(suffix => path.endsWith(suffix)) && form.closest('table')) form.dataset.rowDelete = '';
      else if (standalonePaths.some(suffix => path.endsWith(suffix))) form.dataset.asyncDelete = '';
    });
    document.querySelectorAll('table').forEach(table => {
      const forms = [...table.querySelectorAll('[data-row-delete]')];
      if (!forms.length || enhanced.has(table)) return;
      enhanced.add(table);
      const label = table.caption?.textContent.trim() || table.id;
      let tools = document.querySelector(`[data-record-delete-tools="${table.id}"]`);
      if (!tools) {
        tools = create('div', { class: 'table-tools', 'data-record-delete-tools': table.id });
        tools.append(
          create('button', { type: 'button', class: 'btn btn-sm btn-outline-danger', 'data-delete-selected': '' }, 'Delete selected'),
          create('button', { type: 'button', class: 'btn btn-sm btn-outline-secondary', 'data-delete-clear': '' }, 'Clear selection'),
          create('span', { class: 'form-text', 'data-delete-selected-count': '', 'aria-live': 'polite' }),
          create('span', { class: 'form-text' }, 'Select page affects visible items only. Selections remain across pages and filters.'),
          create('output', { class: 'alert alert-info mb-0', 'data-delete-message': '', 'aria-live': 'polite', hidden: '' }),
        );
        table.parentElement.before(tools);
      }
      let selectPage = table.querySelector('[data-delete-page]');
      if (!selectPage) {
        const head = create('th', { scope: 'col', 'data-sort': 'none' });
        selectPage = create('input', { type: 'checkbox', class: 'form-check-input', 'data-delete-page': '', 'aria-label': `Select deletable ${label} on this page` });
        head.append(selectPage);
        table.tHead.rows[0].prepend(head);
        [...table.tBodies[0].rows].forEach(row => {
          const cell = create('td', {});
          const form = row.querySelector('[data-row-delete]');
          if (form) cell.append(create('input', { type: 'checkbox', class: 'form-check-input', 'data-delete-row': '', 'aria-label': `Select for deletion: ${form.dataset.confirm}` }));
          row.prepend(cell);
        });
      }
      const message = tools.querySelector('[data-delete-message]');
      const selectedCount = tools.querySelector('[data-delete-selected-count]');
      const deleteSelected = tools.querySelector('[data-delete-selected]');
      const clearSelected = tools.querySelector('[data-delete-clear]');
      let heading = table.closest('.table-panel')?.previousElementSibling;
      while (heading && !heading.classList.contains('section-heading')) heading = heading.previousElementSibling;
      const recordCount = document.querySelector(`[data-record-count="${table.id}"]`) || heading?.querySelector('.status');
      const countSuffix = recordCount?.textContent.includes('records') ? ' records' : '';
      let empty = document.querySelector(`[data-record-empty="${table.id}"]`);
      if (!empty) {
        empty = create('p', { class: 'p-3 mb-0', 'data-record-empty': table.id, hidden: '' }, 'No items remain in this view.');
        table.parentElement.after(empty);
      }
      let busy = false;
      const boxes = () => [...table.querySelectorAll('[data-delete-row]')];
      const selected = () => boxes().filter(box => box.checked);
      const visible = () => boxes().filter(box => !box.closest('tr').hidden);
      const update = () => {
        const locked = busy || activeDelete;
        const chosen = selected(), page = visible();
        const hidden = chosen.filter(box => box.closest('tr').hidden).length;
        const hiddenSummary = hidden ? ` (${hidden} on other pages or filtered out)` : '';
        selectedCount.textContent = `${chosen.length} selected${hiddenSummary}`;
        deleteSelected.disabled = locked || !chosen.length;
        clearSelected.disabled = locked || !chosen.length;
        selectPage.disabled = locked || !page.length;
        table.querySelectorAll('[data-row-delete] button, [data-delete-row]').forEach(control => { control.disabled = locked; });
        selectPage.checked = !!page.length && page.every(box => box.checked);
        selectPage.indeterminate = page.some(box => box.checked) && !selectPage.checked;
        const rows = table.querySelectorAll('[data-filter-row]').length;
        if (recordCount) recordCount.textContent = `${rows}${countSuffix}`;
        empty.hidden = rows !== 0;
      };
      const setBusy = value => {
        busy = value;
        setActive(value);
        table.setAttribute('aria-busy', String(value));
        table.querySelectorAll('[data-row-delete] button, [data-delete-row]').forEach(control => { control.disabled = value; });
        update();
      };
      const remove = async forms => {
        if (busy || activeDelete || !forms.length) return;
        const confirmation = forms.length === 1 ? forms[0].dataset.confirm :
          `Delete ${forms.length} selected items from ${label}, including selections on other pages or hidden by filters? This cannot be undone.\n\n${forms.map(form => form.dataset.confirm).join('\n')}`;
        if (!window.confirm(confirmation)) return;
        // Keep exact per-value identities and each form's CSRF token. No bulk
        // privilege bypass, parallel writes, or automatic mutation retries.
        const jobs = forms.map(form => ({ form, body: new FormData(form), row: form.closest('tr') }));
        setBusy(true);
        message.hidden = false;
        message.textContent = `Deleting ${jobs.length} items…`;
        let deleted = 0;
        try {
          const deleteJob = async job => {
            await acknowledge(job.form, job.body);
            job.row.remove();
            deleted++;
            table.dispatchEvent(new Event('table-rows-changed'));
            update();
            message.textContent = `Deleted ${deleted} of ${jobs.length} items…`;
          };
          // Each promise starts only after the preceding acknowledgement;
          // a rejection prevents every later job from being sent.
          await jobs.reduce((pending, job) => pending.then(() => deleteJob(job)), Promise.resolve());
          message.textContent = `Deleted ${deleted} ${deleted === 1 ? 'item' : 'items'}.`;
        } catch {
          // Deliberately omit raw exception details: they may contain private
          // backend data. Report confirmed progress and the recovery action.
          // A missing acknowledgement can mean the write succeeded remotely.
          // Keep uncertain rows and stop the batch; do not silently retry them.
          message.textContent = `Deleted ${deleted} of ${jobs.length} items. Could not confirm the next deletion; remaining rows are kept. Refresh to verify server state before retrying.`;
        } finally {
          setBusy(false);
          document.getElementById(`filter-${table.id}`)?.focus({ preventScroll: true });
        }
      };
      tools.hidden = false;
      table.querySelectorAll('[data-delete-selection]').forEach(cell => { cell.hidden = false; });
      boxes().forEach(box => { box.addEventListener('change', update); });
      selectPage.addEventListener('change', () => {
        visible().forEach(box => { box.checked = selectPage.checked; });
        update();
      });
      clearSelected.addEventListener('click', () => {
        boxes().forEach(box => { box.checked = false; });
        update();
      });
      deleteSelected.addEventListener('click', () => {
        void remove(selected().map(box => box.closest('tr').querySelector('[data-row-delete]')));
      });
      table.querySelectorAll('[data-row-delete]').forEach(form => {
        form.addEventListener('submit', event => { event.preventDefault(); void remove([form]); });
        form.dataset.deleteEnhanced = 'true';
      });
      table.addEventListener('table-rows-rendered', update);
      table.addEventListener('deletion-state-changed', update);
      update();
    });
    document.querySelectorAll('form[data-async-delete]').forEach(form => {
      if (enhanced.has(form)) return;
      enhanced.add(form);
      let busy = false;
      form.addEventListener('submit', async event => {
        event.preventDefault();
        if (busy || activeDelete || !window.confirm(form.dataset.confirm || 'Permanently delete this item?')) return;
        const body = new FormData(form);
        const controls = [...form.querySelectorAll('button, input, select, textarea')];
        const disabled = controls.map(control => control.disabled);
        const message = create('output', { class: 'alert alert-info d-block', 'aria-live': 'polite' }, 'Deleting…');
        form.append(message);
        busy = true;
        setActive(true);
        controls.forEach(control => { control.disabled = true; });
        let acknowledged = false;
        try {
          const result = await acknowledge(form, body);
          acknowledged = true;
          await refreshContent(result.refresh_url);
        } catch {
          // Deliberately redact network/parse exceptions while preserving
          // the acknowledgement state and original-operation recovery link.
          message.textContent = acknowledged ? 'Deletion confirmed, but the view could not be updated. Refresh to load current state; do not repeat the deletion.' :
            'Could not confirm deletion. Check current service state or the original operation before retrying.';
          if (form.dataset.deleteOperationUrl) {
            message.append(create('a', { href: form.dataset.deleteOperationUrl, class: 'btn btn-outline-secondary ms-2' }, 'Check original operation'));
          }
        } finally {
          controls.forEach((control, index) => { control.disabled = disabled[index]; });
          busy = false;
          setActive(false);
        }
      });
      form.dataset.deleteEnhanced = 'true';
    });
  };
  document.addEventListener('DOMContentLoaded', initialize);
  document.addEventListener('netadmin-content-updated', initialize);
})();
