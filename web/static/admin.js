// Comportamentos do painel. Tudo é aprimoramento: as páginas funcionam sem JS.

// Mostra só os campos de configuração do plugin escolhido.
document.querySelectorAll("[data-plugin-select]").forEach((select) => {
  const sync = () =>
    document.querySelectorAll("[data-plugin]").forEach((fs) => {
      fs.hidden = fs.dataset.plugin !== select.value;
    });
  select.addEventListener("change", sync);
});

// Pré-visualização ao vivo: aplica cores e textos no iframe sem salvar.
const frame = document.querySelector("[data-preview]");
if (frame) {
  const apply = () => {
    const doc = frame.contentDocument;
    if (!doc) return;
    document.querySelectorAll("[data-css-var]").forEach((input) => {
      doc.documentElement.style.setProperty(input.dataset.cssVar, input.value);
    });
    document.querySelectorAll("[data-text]").forEach((input) => {
      doc.querySelectorAll(`[data-text="${input.dataset.text}"]`).forEach((el) => {
        el.textContent = input.value;
      });
    });
  };
  document.querySelectorAll("[data-css-var], [data-text]").forEach((input) => input.addEventListener("input", apply));
  frame.addEventListener("load", apply);
}

// Confirmação antes de ações destrutivas.
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (e) => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});
