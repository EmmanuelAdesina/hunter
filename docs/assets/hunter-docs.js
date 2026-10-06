(() => {
  const body = document.body;
  const sidebar = document.getElementById('sidebar');
  const menuToggle = document.getElementById('menuToggle');
  const mobileScrim = document.getElementById('mobileScrim');
  const search = document.getElementById('docSearch');
  const searchStatus = document.getElementById('searchStatus');
  const searchEmpty = document.getElementById('searchEmpty');
  const clearSearch = document.getElementById('clearSearch');
  const toast = document.getElementById('toast');
  const diagramHost = document.getElementById('diagramHost');
  const diagramStatus = document.getElementById('diagramStatus');
  const copyButton = document.getElementById('copyDiagram');
  const sections = Array.from(document.querySelectorAll('.doc-section'));
  const navLinks = Array.from(document.querySelectorAll('.nav-link'));
  const navigationBreakpoint = window.matchMedia('(max-width: 920px)');
  let diagramSource = '';
  let toastTimer = 0;

  const showToast = (message) => {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('is-visible');
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove('is-visible'), 1900);
  };

  const syncNavigation = () => {
    const collapsed = navigationBreakpoint.matches && !body.classList.contains('nav-open');
    sidebar?.setAttribute('aria-hidden', String(collapsed));
    if (collapsed) sidebar?.setAttribute('inert', '');
    else sidebar?.removeAttribute('inert');
  };

  const closeNavigation = () => {
    const returnFocus = navigationBreakpoint.matches && sidebar?.contains(document.activeElement);
    body.classList.remove('nav-open');
    menuToggle?.setAttribute('aria-expanded', 'false');
    menuToggle?.setAttribute('aria-label', 'Open documentation navigation');
    syncNavigation();
    if (returnFocus) menuToggle?.focus();
  };

  menuToggle?.addEventListener('click', () => {
    const open = !body.classList.contains('nav-open');
    body.classList.toggle('nav-open', open);
    menuToggle.setAttribute('aria-expanded', String(open));
    menuToggle.setAttribute('aria-label', open ? 'Close documentation navigation' : 'Open documentation navigation');
    syncNavigation();
    if (open) navLinks.find((link) => !link.classList.contains('search-hidden'))?.focus();
  });
  navigationBreakpoint.addEventListener?.('change', syncNavigation);
  syncNavigation();
  mobileScrim?.addEventListener('click', closeNavigation);
  navLinks.forEach((link) => link.addEventListener('click', closeNavigation));

  const activeLinks = new Map(navLinks.map((link) => [link.hash.slice(1), link]));
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      navLinks.forEach((link) => link.classList.remove('is-active'));
      activeLinks.get(visible.target.id)?.classList.add('is-active');
    }, { rootMargin: '-16% 0px -68% 0px', threshold: [0, .15, .35] });
    sections.forEach((section) => observer.observe(section));
  }

  search?.addEventListener('input', () => {
    const query = search.value.trim().toLowerCase();
    let matches = 0;
    sections.forEach((section) => {
      const hit = !query || section.textContent.toLowerCase().includes(query);
      section.classList.toggle('search-hidden', !hit);
      if (hit) matches += 1;
    });
    navLinks.forEach((link) => {
      const section = document.getElementById(link.hash.slice(1));
      const hit = !query || (section && section.textContent.toLowerCase().includes(query));
      link.classList.toggle('search-hidden', !hit);
    });
    if (searchStatus) searchStatus.textContent = query ? `${matches} matching documentation section${matches === 1 ? '' : 's'}` : '';
    if (searchEmpty) searchEmpty.hidden = !query || matches > 0;
  });

  clearSearch?.addEventListener('click', () => {
    if (!search) return;
    search.value = '';
    search.dispatchEvent(new Event('input', { bubbles: true }));
    search.focus();
  });

  const themeToggle = document.getElementById('themeToggle');
  themeToggle?.addEventListener('click', () => {
    const enabled = !body.classList.contains('high-contrast');
    body.classList.toggle('high-contrast', enabled);
    themeToggle.setAttribute('aria-pressed', String(enabled));
    showToast(enabled ? 'High contrast enabled' : 'Standard contrast enabled');
  });

  document.addEventListener('keydown', (event) => {
    const target = event.target;
    const typing = target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
    if (event.key === '/' && !typing) {
      event.preventDefault();
      search?.focus();
    }
    if (event.key === 'Escape') {
      closeNavigation();
      if (document.activeElement === search) search.blur();
    }
  });

  const showDiagramSource = (source, status) => {
    if (!diagramHost) return;
    diagramHost.replaceChildren();
    const pre = document.createElement('pre');
    pre.className = 'diagram-source';
    pre.textContent = source || 'The Mermaid source could not be loaded.';
    diagramHost.appendChild(pre);
    diagramHost.setAttribute('aria-busy', 'false');
    if (diagramStatus) diagramStatus.textContent = status;
  };

  const loadMermaid = () => {
    if (window.mermaid) return Promise.resolve(true);
    return new Promise((resolve) => {
      const script = document.createElement('script');
      let settled = false;
      const finish = (available) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        resolve(available);
      };
      const timeout = window.setTimeout(() => finish(false), 2600);
      script.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
      script.async = true;
      script.referrerPolicy = 'no-referrer';
      script.onload = () => finish(Boolean(window.mermaid));
      script.onerror = () => finish(false);
      document.head.appendChild(script);
    });
  };

  const renderDiagram = async () => {
    try {
      const response = await fetch('./hunter-end-to-end.md', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const markdown = await response.text();
      const match = markdown.match(/```mermaid\s*([\s\S]*?)```/i);
      if (!match) throw new Error('No Mermaid code block found');
      diagramSource = match[1].trim();
      if (copyButton) {
        copyButton.disabled = false;
        copyButton.title = 'Copy Mermaid source';
      }

      showDiagramSource(diagramSource, 'Loading diagram renderer…');
      if (!(await loadMermaid())) {
        showDiagramSource(diagramSource, 'Mermaid runtime unavailable; source is shown below');
        return;
      }

      window.mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
        flowchart: { htmlLabels: true, curve: 'basis', nodeSpacing: 36, rankSpacing: 48, useMaxWidth: false },
        themeVariables: {
          primaryColor: '#f0f5fb',
          primaryTextColor: '#172b43',
          primaryBorderColor: '#8da8c4',
          lineColor: '#8a9db2',
          secondaryColor: '#e8f7f1',
          tertiaryColor: '#fff5e6',
          fontSize: '13px',
          edgeLabelBackground: '#ffffff',
          clusterBkg: '#f8fafc',
          clusterBorder: '#dbe4ec'
        }
      });
      const { svg, bindFunctions } = await window.mermaid.render('hunterRuntimeGraph', diagramSource);
      diagramHost.innerHTML = svg;
      diagramHost.setAttribute('aria-busy', 'false');
      bindFunctions?.(diagramHost);
      if (diagramStatus) diagramStatus.textContent = 'Rendered from the canonical Mermaid source';
    } catch (error) {
      if (copyButton) {
        copyButton.disabled = !diagramSource;
        copyButton.title = diagramSource ? 'Copy Mermaid source' : 'Canonical Mermaid source unavailable';
      }
      const status = diagramSource
        ? `Diagram rendering failed (${error.message}); Mermaid source shown`
        : `Canonical Mermaid source could not be loaded (${error.message})`;
      showDiagramSource(diagramSource, status);
    }
  };

  copyButton?.addEventListener('click', async () => {
    if (!diagramSource) return;
    try {
      await navigator.clipboard.writeText(diagramSource);
      showToast('Mermaid source copied');
    } catch (_) {
      showToast('Clipboard permission unavailable');
    }
  });

  renderDiagram();
})();
