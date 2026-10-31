/* Local interface enhancements. Server-rendered navigation and forms work without JS. */
(() => {
  'use strict';
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { preference = localStorage.getItem('netadmin-theme') || 'system'; } catch (_) { /* Storage may be disabled. */ }
  if (!['system', 'light', 'dark'].includes(preference)) preference = 'system';
  const apply = () => { root.dataset.bsTheme = preference === 'system' ? (system.matches ? 'dark' : 'light') : preference; };
  apply();
  system.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-control]').forEach(control => { control.hidden = false; });
    document.querySelectorAll('[data-theme-choice]').forEach(choice => {
      choice.value = preference;
      choice.addEventListener('change', () => {
        preference = choice.value;
        try { localStorage.setItem('netadmin-theme', preference); } catch (_) { /* Keep this session's choice. */ }
        apply();
      });
    });
    document.querySelectorAll('[data-filter-tools]').forEach(control => { control.hidden = false; });
    document.querySelectorAll('[data-table-filter]').forEach(input => {
      const table = document.getElementById(input.dataset.tableFilter);
      if (!table) return;
      const rows = [...table.querySelectorAll('[data-filter-row]')];
      const count = document.querySelector(`[data-filter-count="${table.id}"]`);
      const filter = () => {
        const query = input.value.trim().toLocaleLowerCase();
        let visible = 0;
        rows.forEach(row => { row.hidden = !row.textContent.toLocaleLowerCase().includes(query); if (!row.hidden) visible++; });
        if (count) count.textContent = `${visible} of ${rows.length} shown`;
      };
      input.addEventListener('input', filter);
      filter();
    });
    document.querySelectorAll('form[data-confirm]').forEach(form => {
      form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
      });
    });
  });
})();
