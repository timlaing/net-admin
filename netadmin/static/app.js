/* Local interface enhancements. Server-rendered navigation and forms work without JS. */
(() => {
  'use strict';
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { preference = localStorage.getItem('netadmin-theme') || 'system'; } catch (_) { /* Storage may be disabled. */ }
  if (!['system', 'light', 'dark'].includes(preference)) preference = 'system';
  const apply = () => {
    let theme = preference;
    if (preference === 'system') theme = system.matches ? 'dark' : 'light';
    root.dataset.bsTheme = theme;
  };
  apply();
  system.addEventListener('change', apply);
  const missingSortValue = text => !text || text === '—';
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const setupTableSorting = table => {
    const body = table.tBodies[0];
    if (!body || !table.tHead) return;
    const headers = [...table.tHead.rows[0].cells];
    headers.forEach((header, column) => {
      const label = header.textContent.trim();
      if (header.dataset.sort === 'none' || ['Actions', 'Details'].includes(label)) return;
      header.scope = 'col';
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'table-sort';
      button.textContent = label;
      const indicator = document.createElement('span');
      indicator.className = 'sort-indicator';
      indicator.setAttribute('aria-hidden', 'true');
      indicator.textContent = '↕';
      button.append(indicator);
      header.replaceChildren(button);
      header.setAttribute('aria-sort', 'none');
      button.addEventListener('click', () => {
        const descending = header.getAttribute('aria-sort') === 'ascending';
        const value = row => {
          const cell = row.cells[column];
          const text = cell.dataset.sortValue ?? cell.textContent.trim();
          // ISC lease dates include a weekday number before the year.
          return label === 'Ends' ? text.replace(/^[0-6]\s+(?=\d{4}\/\d{2}\/\d{2})/, '') : text;
        };
        const rows = [...body.rows];
        rows.sort((a, b) => {
          const left = value(a), right = value(b);
          // Missing values remain last in either direction.
          if (missingSortValue(left) || missingSortValue(right)) return Number(missingSortValue(left)) - Number(missingSortValue(right));
          return collator.compare(left, right) * (descending ? -1 : 1);
        });
        rows.forEach(row => body.append(row));
        headers.forEach(other => {
          if (!other.hasAttribute('aria-sort')) return;
          other.setAttribute('aria-sort', 'none');
          other.querySelector('.sort-indicator').textContent = '↕';
        });
        header.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
        indicator.textContent = descending ? '↓' : '↑';
        table.dispatchEvent(new Event('table-sorted'));
      });
    });
  };
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-connection-status-url]').forEach(card => {
      const badge = card.querySelector('[data-connection-state]');
      const message = card.querySelector('[data-connection-message]');
      const checked = card.querySelector('[data-connection-checked]');
      const access = card.querySelector('[data-connection-access]');
      const update = async () => {
        if (document.hidden) return;
        try {
          const response = await fetch(card.dataset.connectionStatusUrl, {
            credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(8000),
          });
          if (!response.ok || response.redirected) throw new Error('Status unavailable');
          const result = await response.json();
          badge.textContent = result.state;
          if (access) access.textContent = result.state === 'Direct Bind' ? 'Direct Bind' : (result.access_mode || 'Unknown');
          badge.classList.toggle('status-success', result.state === 'Connected');
          badge.classList.toggle('status-warning', result.state !== 'Connected');
          message.textContent = result.message;
          checked.textContent = `Checked ${new Date(result.checked_at * 1000).toLocaleTimeString()}`;
        } catch (error) {
          const timedOut = error.name === 'TimeoutError' || error.name === 'AbortError';
          badge.textContent = 'Unavailable';
          if (access) access.textContent = 'Unknown';
          badge.classList.remove('status-success');
          badge.classList.add('status-warning');
          message.textContent = timedOut ? 'Connection check timed out. Open Settings for diagnostics.' : 'Could not check this connection. Open Settings for diagnostics.';
          checked.textContent = 'Last check failed';
        }
      };
      void update();
      window.setInterval(() => { void update(); }, 30000);
    });
    const dnsMode = document.getElementById('dns_use_agent');
    if (dnsMode) {
      const updateDnsMode = () => {
        document.querySelectorAll('[data-direct-dns]').forEach(section => {
          section.hidden = dnsMode.checked;
          section.open = !dnsMode.checked;
        });
        document.querySelectorAll('[data-dns-agent-field]').forEach(field => { field.hidden = !dnsMode.checked; });
      };
      dnsMode.addEventListener('change', updateDnsMode);
      updateDnsMode();
    }
    document.querySelectorAll('[data-scroll-region]').forEach(region => {
      // Native scrolling accepts arrow keys once focused. Avoid extra Tab stops
      // when the complete table already fits in the available width.
      const updateFocus = () => { region.tabIndex = region.scrollWidth > region.clientWidth ? 0 : -1; };
      updateFocus();
      const observer = new ResizeObserver(updateFocus);
      observer.observe(region);
      const table = region.querySelector('table');
      if (table) observer.observe(table);
    });
    document.querySelectorAll('[data-theme-control]').forEach(control => { control.hidden = false; });
    document.querySelectorAll('[data-theme-choice]').forEach(choice => {
      choice.value = preference;
      choice.addEventListener('change', () => {
        preference = choice.value;
        try { localStorage.setItem('netadmin-theme', preference); } catch (_) { /* Keep this session's choice. */ }
        apply();
      });
    });
    document.querySelectorAll('table').forEach(setupTableSorting);
    document.querySelectorAll('[data-filter-tools]').forEach(control => { control.hidden = false; });
    document.querySelectorAll('[data-table-filter]').forEach(input => {
      const table = document.getElementById(input.dataset.tableFilter);
      if (!table) return;
      const count = document.querySelector(`[data-filter-count="${table.id}"]`);
      const tools = input.closest('[data-filter-tools]');
      const size = tools.querySelector('[data-page-size]');
      const previous = tools.querySelector('[data-page-previous]');
      const next = tools.querySelector('[data-page-next]');
      const position = tools.querySelector('[data-page-position]');
      let page = 1;
      const render = () => {
        const rows = [...table.querySelectorAll('[data-filter-row]')];
        const query = input.value.trim().toLocaleLowerCase();
        const matching = rows.filter(row => row.textContent.toLocaleLowerCase().includes(query));
        const pageSize = Number(size.value);
        const pages = Math.max(1, Math.ceil(matching.length / pageSize));
        page = Math.min(page, pages);
        const start = (page - 1) * pageSize;
        rows.forEach(row => { row.hidden = true; });
        matching.slice(start, start + pageSize).forEach(row => { row.hidden = false; });
        if (count) count.textContent = matching.length ? `${start + 1}–${Math.min(start + pageSize, matching.length)} of ${matching.length} (${rows.length} total)` : `0 of ${rows.length} matches`;
        position.textContent = `Page ${page} of ${pages}`;
        previous.disabled = page === 1;
        next.disabled = page === pages;
      };
      table.addEventListener('table-sorted', () => { page = 1; render(); });
      input.addEventListener('input', () => { page = 1; render(); });
      size.addEventListener('change', () => { page = 1; render(); });
      previous.addEventListener('click', () => { page--; render(); });
      next.addEventListener('click', () => { page++; render(); });
      render();
    });
    document.querySelectorAll('[data-edit-client]').forEach(button => {
      button.addEventListener('click', () => {
        const form = document.getElementById('client-form');
        ['name', 'address', 'shortname'].forEach(name => { form.elements[name].value = button.dataset[name] || ''; });
        form.elements.name.readOnly = true;
        form.elements.secret.value = '';
        form.closest('details').open = true;
        form.scrollIntoView({ block: 'center' });
        form.elements.address.focus();
      });
    });
    document.querySelectorAll('[data-new-client]').forEach(button => {
      button.addEventListener('click', () => {
        const form = document.getElementById('client-form');
        form.reset();
        form.elements.name.readOnly = false;
        form.elements.name.focus();
      });
    });
    document.querySelectorAll('form[data-csr-issue]').forEach(form => {
      const csr = form.querySelector('[name="csr"]');
      const approval = form.querySelector('[name="confirm"]');
      csr.addEventListener('input', () => {
        approval.checked = false;
        document.querySelectorAll('[data-csr-preview]').forEach(preview => { preview.hidden = true; });
      });
    });
    document.querySelectorAll('form[data-confirm]').forEach(form => {
      form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
      });
    });
  });
})();
