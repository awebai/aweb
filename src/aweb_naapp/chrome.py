"""Shared site chrome for naapp surfaces: head, header, footer, scripts, and the
copy button. An app supplies a :class:`SiteConfig` (brand, nav, footer) and the
chrome renders identically across every naapp. The scripts live in plain string
constants (not f-strings) so the JS braces need no escaping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from aweb_naapp.css import CSS_SHA256

COPY_BTN = (
    '<button class="copy-btn" type="button" aria-label="Copy command">'
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>'
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>'
)

_THEME_INIT_SCRIPT = """  <script>
    (function () {
      try {
        var t = localStorage.getItem('aweb-theme');
        if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
      } catch (e) {}
    })();
  </script>"""

_SITE_SCRIPT_BODY = """    function awebToggleTheme() {
      var el = document.documentElement;
      var cur = el.getAttribute('data-theme');
      if (!cur) {
        cur = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      var next = cur === 'dark' ? 'light' : 'dark';
      el.setAttribute('data-theme', next);
      try { localStorage.setItem('aweb-theme', next); } catch (e) {}
    }
    Array.prototype.forEach.call(document.querySelectorAll('.cmd .copy-btn'), function (button) {
      button.addEventListener('click', function () {
        var pre = button.parentElement.querySelector('pre');
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(function () {
          button.classList.add('copied');
          setTimeout(function () { button.classList.remove('copied'); }, 1600);
        });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('.split-btn'), function (sb) {
      var url = sb.getAttribute('data-llms-url');
      var caret = sb.querySelector('.split-btn__caret');
      var main = sb.querySelector('.split-btn__main');
      var label = main ? main.querySelector('.split-btn__label') : null;
      function items() { return Array.prototype.slice.call(sb.querySelectorAll('.split-btn__item')); }
      function close() { sb.setAttribute('data-open', 'false'); if (caret) caret.setAttribute('aria-expanded', 'false'); }
      function open() { sb.setAttribute('data-open', 'true'); if (caret) caret.setAttribute('aria-expanded', 'true'); }
      function doCopy() {
        fetch(url).then(function (r) { return r.text(); }).then(function (text) {
          navigator.clipboard.writeText(text).then(function () {
            if (!main) return;
            main.classList.add('copied');
            if (label) label.textContent = 'Copied!';
            main.setAttribute('aria-label', 'Copied to clipboard');
            setTimeout(function () {
              main.classList.remove('copied');
              if (label) label.textContent = 'llms.txt';
              main.setAttribute('aria-label', 'Copy llms.txt to clipboard');
            }, 1600);
          });
        });
      }
      Array.prototype.forEach.call(sb.querySelectorAll('[data-llms-copy]'), function (b) {
        b.addEventListener('click', function () { doCopy(); if (b.getAttribute('role') === 'menuitem') close(); });
      });
      if (caret) caret.addEventListener('click', function (e) {
        e.stopPropagation();
        if (sb.getAttribute('data-open') === 'true') { close(); } else { open(); var it = items()[0]; if (it) it.focus(); }
      });
      sb.addEventListener('keydown', function (e) {
        if (sb.getAttribute('data-open') !== 'true') return;
        var list = items(); var i = list.indexOf(document.activeElement);
        if (e.key === 'ArrowDown') { e.preventDefault(); (list[i + 1] || list[0]).focus(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); (list[i - 1] || list[list.length - 1]).focus(); }
        else if (e.key === 'Escape') { close(); if (caret) caret.focus(); }
      });
      document.addEventListener('click', function (e) { if (!sb.contains(e.target)) close(); });
    });
    // Reference page: highlight the sidebar link for the operation in view.
    var refOps = document.querySelectorAll('.ref-op[id]');
    if (refOps.length && 'IntersectionObserver' in window) {
      var refLinks = {};
      Array.prototype.forEach.call(document.querySelectorAll('.ref-sidebar a[href^="#"]'), function (a) {
        refLinks[a.getAttribute('href').slice(1)] = a;
      });
      var refSpy = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          var link = refLinks[e.target.id];
          if (!link) return;
          Array.prototype.forEach.call(document.querySelectorAll('.ref-sidebar a.active'), function (a) { a.classList.remove('active'); });
          link.classList.add('active');
        });
      }, { rootMargin: '-80px 0px -68% 0px' });
      Array.prototype.forEach.call(refOps, function (op) { refSpy.observe(op); });
    }"""


@dataclass(frozen=True)
class NavLink:
    label: str
    href: str


@dataclass(frozen=True)
class FooterColumn:
    heading: str
    links: tuple[NavLink, ...]


@dataclass(frozen=True)
class SiteConfig:
    """Everything app-specific in the shared chrome. Passing an app's exact config
    reproduces its chrome byte for byte."""

    origin: str
    brand: str
    title: str
    description: str
    nav_links: tuple[NavLink, ...]
    footer_blurb: str
    footer_columns: tuple[FooterColumn, ...]
    footer_bottom: str
    # Secondary buttons in the header-right; the standard llms.txt split control is
    # always rendered after them, so it is not listed here.
    header_actions: tuple[NavLink, ...] = field(
        default_factory=lambda: (NavLink("aweb.ai", "https://aweb.ai"),)
    )
    # The app's public source repo. When set, a GitHub-logo link shows in the
    # header and an "open source, MIT-licensed" line in the footer.
    source_url: str | None = None
    # The social-card image path (1200x630), served by the app. When set, it is
    # the og:image / twitter:image for link previews (WhatsApp, Slack, X, etc.).
    og_image: str | None = None

    @property
    def origin_html(self) -> str:
        return escape(self.origin.rstrip("/"), quote=True)


# The standard llms.txt control: a split button (copy llms.txt) with a caret that
# opens an opaque menu (copy / open). Present in the header of every aweb naapp.
_LLMS_CONTROL = """        <div class="split-btn" data-llms-url="/llms.txt">
          <button class="split-btn__main" type="button" data-llms-copy aria-label="Copy llms.txt to clipboard" title="The plain-text guide for LLMs and agents">
            <svg class="icon-clip" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <svg class="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
            <span class="split-btn__label">llms.txt</span>
          </button>
          <button class="split-btn__caret" type="button" aria-haspopup="true" aria-expanded="false" aria-controls="llms-menu" aria-label="More llms.txt options">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <div class="split-btn__menu" id="llms-menu" role="menu">
            <button class="split-btn__item" type="button" role="menuitem" data-llms-copy>
              <span class="lead">Copy for LLMs</span><span class="sub">Copy llms.txt to clipboard</span>
            </button>
            <a class="split-btn__item" role="menuitem" href="/llms.txt" target="_blank" rel="noopener">
              <span class="lead">Open llms.txt</span><span class="sub">View the plain-text guide</span>
            </a>
          </div>
        </div>"""


_GITHUB_ICON = (
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">'
    '<path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55'
    "v-1.93c-3.2.69-3.87-1.54-3.87-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.7.08-.7"
    " 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53"
    "-2.55-.29-5.23-1.28-5.23-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05"
    " 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.21-1.49 3.18-1.18 3.18-1.18.62 1.59.23 2.76.11 3.05"
    ".74.81 1.18 1.84 1.18 3.1 0 4.42-2.69 5.39-5.25 5.68.41.35.78 1.05.78 2.11"
    'v3.13c0 .3.21.66.79.55C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z"/></svg>'
)


def render_head(site: SiteConfig) -> str:
    origin = site.origin_html
    title = escape(site.title, quote=True)
    desc = escape(site.description, quote=True)
    # Fingerprint the stylesheet URL with the css content hash so a CDN edge never
    # serves a stale /css/aweb.css after a toolkit css change — every rev is a new
    # URL. The app serves /css/aweb.<hash>.css (and the legacy /css/aweb.css).
    css_href = f"/css/aweb.{CSS_SHA256[:12]}.css"
    og_image = ""
    if site.og_image:
        img = f"{origin}{escape(site.og_image, quote=True)}"
        og_image = (
            f'\n  <meta property="og:image" content="{img}">'
            '\n  <meta property="og:image:width" content="1200">'
            '\n  <meta property="og:image:height" content="630">'
            f'\n  <meta property="og:image:alt" content="{title}">'
            f'\n  <meta name="twitter:image" content="{img}">'
        )
    return f"""<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(site.title)}</title>
  <meta name="description" content="{desc}">
  <link rel="canonical" href="{origin}/">
  <meta name="theme-color" content="#faf7f2" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0a0705" media="(prefers-color-scheme: dark)">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="{escape(site.brand, quote=True)}">
  <meta property="og:title" content="{title}">
  <meta property="og:description" content="{desc}">
  <meta property="og:url" content="{origin}/">
  <meta property="og:locale" content="en_US">{og_image}
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{title}">
  <meta name="twitter:description" content="{desc}">
{_THEME_INIT_SCRIPT}
  <link rel="stylesheet" href="{css_href}">
</head>"""


def render_header(site: SiteConfig) -> str:
    # aweb / awid nav links carry the brand-mark (mono + accent), like the wordmarks
    # in body copy; other nav links use the plain nav style.
    nav = "\n".join(
        f'        <a href="{link.href}"'
        + (' class="brand-mark"' if link.label.lower() in ("aweb", "awid") else "")
        + f">{link.label}</a>"
        for link in site.nav_links
    )
    actions = "".join(
        f'\n        <a class="btn secondary" href="{a.href}">{a.label}</a>' for a in site.header_actions
    )
    gh = (
        f'\n        <a class="gh-link" href="{escape(site.source_url, quote=True)}" target="_blank"'
        f' rel="noopener" aria-label="Source on GitHub" title="Source on GitHub">{_GITHUB_ICON}</a>'
        if site.source_url
        else ""
    )
    return f"""  <header class="site-header">
    <div class="wrap">
      <a class="brand" href="/"><span class="dot"></span>{site.brand}</a>
      <nav class="nav-links">
{nav}
      </nav>
      <div class="header-right">
        <button class="theme-toggle" type="button" aria-label="Toggle dark mode" onclick="awebToggleTheme()">
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
        </button>{gh}{actions}
{_LLMS_CONTROL}
      </div>
    </div>
  </header>"""


def render_footer(site: SiteConfig) -> str:
    cols = "\n".join(
        '        <div class="footer-col">\n'
        f"          <h4>{col.heading}</h4>\n"
        + "\n".join(
            f'          <a href="{link.href}"'
            + (' class="brand-mark"' if link.label.lower() in ("aweb", "awid") else "")
            + f">{link.label}</a>"
            for link in col.links
        )
        + "\n        </div>"
        for col in site.footer_columns
    )
    oss = (
        f'\n          <p class="footer-oss">Open source, MIT-licensed. '
        f'<a href="{escape(site.source_url, quote=True)}" target="_blank" rel="noopener">'
        "View on GitHub &rarr;</a></p>"
        if site.source_url
        else ""
    )
    return f"""  <footer class="site-footer">
    <div class="wrap">
      <div class="footer-cols">
        <div class="footer-brand">
          <a class="brand" href="/"><span class="dot"></span>{site.brand}</a>
          <p>{site.footer_blurb}</p>{oss}
        </div>
{cols}
      </div>
      <div class="footer-bottom">{site.footer_bottom} Origin: {site.origin_html}</div>
    </div>
  </footer>"""


def render_scripts() -> str:
    return f"  <script>\n{_SITE_SCRIPT_BODY}\n  </script>"


def page(site: SiteConfig, body_html: str) -> str:
    """Wrap an app-supplied ``<main>`` body in the shared chrome — a complete HTML
    document with the head, header, footer, and scripts."""
    return f"""<!doctype html>
<html lang="en">
{render_head(site)}
<body>
{render_header(site)}
  <main>
{body_html}
  </main>
{render_footer(site)}
{render_scripts()}
</body>
</html>"""
