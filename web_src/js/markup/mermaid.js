const MAX_SOURCE_CHARACTERS = 5000;

function displayError(el, err) {
  el.closest('pre').classList.remove('is-loading');
  const errorNode = document.createElement('div');
  errorNode.setAttribute('class', 'ui message error markup-block-error mono');
  errorNode.textContent = err.str || err.message || String(err);
  el.closest('pre').before(errorNode);
}

export async function renderMermaid(els) {
  if (!els || !els.length) return;

  const {default: mermaid} = await import(/* webpackChunkName: "mermaid" */'mermaid');

  mermaid.initialize({
    mermaid: {
      startOnLoad: false,
    },
    flowchart: {
      useMaxWidth: true,
      htmlLabels: false,
    },
    theme: 'neutral',
    securityLevel: 'strict',
  });

  for (const el of els) {
    if (el.textContent.length > MAX_SOURCE_CHARACTERS) {
      displayError(el, new Error(`Mermaid source of ${el.textContent.length} characters exceeds the maximum allowed length of ${MAX_SOURCE_CHARACTERS}.`));
      continue;
    }

    let valid;
    try {
      valid = mermaid.parse(el.textContent);
    } catch (err) {
      displayError(el, err);
    }

    if (!valid) {
      el.closest('pre').classList.remove('is-loading');
      continue;
    }

    try {
      mermaid.init(undefined, el, (id) => {
        const svg = document.getElementById(id);
        svg.classList.add('mermaid-chart');
        svg.closest('pre').replaceWith(svg);
      });
    } catch (err) {
      displayError(el, err);
    }
  }
}
