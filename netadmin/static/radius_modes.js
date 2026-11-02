"use strict";
const modeForm = document.querySelector("[data-radius-modes]");
if (modeForm) {
  const certificatePanel = modeForm.querySelector("[data-mode-certificates]");
  const preferred = modeForm.querySelector('[name="preferred"]');
  const save = modeForm.querySelector('button');
  function updateModes() {
    const enabled = Array.from(modeForm.querySelectorAll('[name="enabled"]:checked'))
      .map(input => input.value);
    certificatePanel.hidden = !enabled.some(mode => mode === "peap" || mode === "tls");
    for (const option of preferred.options) {
      option.disabled = !enabled.includes(option.value);
    }
    if (!enabled.includes(preferred.value)) preferred.value = enabled[0] || "";
    save.disabled = enabled.length === 0;
  }
  modeForm.addEventListener("change", updateModes);
  updateModes();
}
