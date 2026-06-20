"""Shared site chrome for naapp surfaces: head, header, footer, scripts, and the
copy button. An app supplies a :class:`SiteConfig` (brand, nav, footer) and the
chrome renders identically across every naapp. The scripts live in plain string
constants (not f-strings) so the JS braces need no escaping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

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
    });"""

_COPY_LLMS_SCRIPT = """    var llmsBtn = document.getElementById('copy-llms');
    if (llmsBtn) {
      llmsBtn.addEventListener('click', function () {
        fetch(llmsBtn.getAttribute('data-llms-url')).then(function (r) { return r.text(); }).then(function (text) {
          navigator.clipboard.writeText(text).then(function () {
            var label = llmsBtn.textContent;
            llmsBtn.classList.add('copied');
            llmsBtn.textContent = 'Copied llms.txt';
            setTimeout(function () { llmsBtn.classList.remove('copied'); llmsBtn.textContent = label; }, 1600);
          });
        });
      });
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
    header_actions: tuple[NavLink, ...] = field(
        default_factory=lambda: (
            NavLink("aweb.ai", "https://aweb.ai"),
            NavLink("Read llms.txt", "/llms.txt"),
        )
    )

    @property
    def origin_html(self) -> str:
        return escape(self.origin.rstrip("/"), quote=True)


_READ_ARROW = (
    ' <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" '
    'stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/>'
    '<path d="m13 6 6 6-6 6"/></svg>'
)


def render_head(site: SiteConfig) -> str:
    return f"""<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{escape(site.description, quote=True)}">
  <meta name="theme-color" content="#faf7f2" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0a0705" media="(prefers-color-scheme: dark)">
  <title>{escape(site.title)}</title>
{_THEME_INIT_SCRIPT}
  <link rel="stylesheet" href="/css/aweb.css">
</head>"""


def render_header(site: SiteConfig) -> str:
    nav = "\n".join(f'        <a href="{link.href}">{link.label}</a>' for link in site.nav_links)
    # The header-right actions: a secondary button for each but the last, then a
    # primary "Read llms.txt"-style action with the arrow.
    *secondary, primary = site.header_actions
    secondary_html = "".join(
        f'\n        <a class="btn secondary" href="{a.href}">{a.label}</a>' for a in secondary
    )
    primary_label = f"{primary.label}{_READ_ARROW}" if primary.label == "Read llms.txt" else primary.label
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
        </button>{secondary_html}
        <a class="btn primary" href="{primary.href}">{primary_label}</a>
      </div>
    </div>
  </header>"""


def render_footer(site: SiteConfig) -> str:
    cols = "\n".join(
        '        <div class="footer-col">\n'
        f"          <h4>{col.heading}</h4>\n"
        + "\n".join(f'          <a href="{link.href}">{link.label}</a>' for link in col.links)
        + "\n        </div>"
        for col in site.footer_columns
    )
    return f"""  <footer class="site-footer">
    <div class="wrap">
      <div class="footer-cols">
        <div class="footer-brand">
          <a class="brand" href="/"><span class="dot"></span>{site.brand}</a>
          <p>{site.footer_blurb}</p>
        </div>
{cols}
      </div>
      <div class="footer-bottom">{site.footer_bottom} Origin: {site.origin_html}</div>
    </div>
  </footer>"""


def render_scripts(*, include_copy_llms: bool = False) -> str:
    body = _SITE_SCRIPT_BODY
    if include_copy_llms:
        body = f"{body}\n{_COPY_LLMS_SCRIPT}"
    return f"  <script>\n{body}\n  </script>"


def page(site: SiteConfig, body_html: str, *, include_copy_llms: bool = False) -> str:
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
{render_scripts(include_copy_llms=include_copy_llms)}
</body>
</html>"""
