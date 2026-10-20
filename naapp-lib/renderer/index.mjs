import { messages } from './catalogs.mjs';
import { renderMarkdown, safeLink } from './sanitize.mjs';

export function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
const known = new Set(['heading', 'text', 'stat', 'status_badge', 'stack', 'grid']);

/** Mount only authorized snapshots validated by aweb_naapp.pages. Host chrome
 * nodes must be outside root. Authority and secrets belong to the adapter. */
export function createPageRenderer({ root, destinations, announcements, host = {}, memberLocale }) {
  if (root.contains(destinations) || root.contains(announcements)) throw new TypeError('Host chrome must be outside the page');
  let current;
  function update(page) {
    current = page;
    const { locale, t } = messages(memberLocale, page?.locale);
    root.lang = locale;
    destinations.replaceChildren(element('h2', t.destinations));
    root.replaceChildren();
    if (page?.page_format !== 'aweb.page/1' || !Array.isArray(page.layout)) {
      const error = element('p', t.unsupported, 'page-error');
      error.setAttribute('role', 'alert'); root.append(error); return;
    }
    root.append(element('p', `aweb / ${page.page_id}`, 'eyebrow'), element('h1', page.title, 'page-title'));
    const domainSet = new Set();
    function rememberLink(url) {
      if (!domainSet.has(url.host)) {
        domainSet.add(url.host); destinations.append(element('bdi', url.host, 'destination-domain'));
      }
    }
    function widget(w) {
      const supported = known.has(w.type);
      const p = supported ? w.props : {};
      const state = page.widget_state?.[w.id] || {};
      const box = element('section', null, `widget widget-${supported ? w.type : 'unknown'}`);
      box.dataset.widget = w.id;
      box.setAttribute('aria-busy', String(!!state.busy));
      if (!supported) box.append(element('p', t.unavailable, 'widget-label'), element('p', w.fallback));
      else if (w.type === 'heading') box.append(element(`h${p.level}`, p.text));
      else if (w.type === 'text') {
        const body = element('div', null, 'markdown'); renderMarkdown(body, p.markdown);
        for (const link of body.querySelectorAll('a[href]')) { const url = safeLink(link.href); if (url) rememberLink(url); }
        box.append(body);
      } else if (w.type === 'stack' || w.type === 'grid') {
        box.classList.add(`gap-${p.gap || 'medium'}`);
        if (w.type === 'grid') box.classList.add(`columns-${p.columns}`);
        box.append(...w.children.map(widget));
      } else {
        const records = page.collections?.find(c => c.id === w.bind?.collection)?.records || [];
        const value = p.field ? records[0]?.value?.[p.field] : p.value;
        box.append(element('p', p.label, 'widget-label'));
        if (w.type === 'stat') {
          box.append(element('bdi', typeof value === 'number' ? new Intl.NumberFormat(locale).format(value) : value ?? '—', 'stat-value'));
          if (p.unit) box.append(element('span', p.unit, 'stat-unit'));
        } else {
          box.append(element('bdi', p.field ? value ?? '—' : p.label, `badge tone-${p.tone}`));
        }
      }
      if (state.message) box.append(element('p', state.message, 'state-message'));
      if (state.progress !== undefined) {
        const progress = element('progress'); progress.max = 100; progress.value = state.progress;
        progress.setAttribute('aria-label', `${p.label || w.id}: ${t.progress}`); box.append(progress);
      }
      if (state.busy) box.append(element('span', t.busy, 'busy-label'));
      return box;
    }
    root.append(...page.layout.map(widget));
    if (domainSet.size === 0) destinations.hidden = true; else destinations.hidden = false;
  }
  return { update, clear() { current = null; root.replaceChildren(); destinations.replaceChildren(); announcements.textContent = ''; }, get page() { return current; } };
}
