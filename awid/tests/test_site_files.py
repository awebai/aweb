from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_hugo_site_scaffold_exists() -> None:
    assert (ROOT / "site" / "hugo.toml").is_file()
    assert (ROOT / "site" / "content" / "_index.md").is_file()
    assert (ROOT / "site" / "layouts" / "index.html").is_file()


def _site_html() -> str:
    return (ROOT / "site" / "layouts" / "index.html").read_text(encoding="utf-8")


def test_hugo_site_serves_and_links_llms_txt() -> None:
    llms = (ROOT / "site" / "static" / "llms.txt").read_text(encoding="utf-8")
    assert llms.startswith("# awid.ai")
    for fact in ("_awid.acme.com", "registry=", "NAAPP", "aw init --new-account", "GET /v1/did/{did_aw}/key"):
        assert fact in llms
    html = _site_html()
    assert '<link rel="alternate" type="text/markdown" href="/llms.txt"' in html
    nav = html[html.index("<nav>") : html.index("</nav>")]
    assert 'href="/llms.txt"' in nav
    hero = html[html.index('<section class="hero">') : html.index("</section>")]
    assert 'href="/llms.txt"' in hero


def test_hugo_site_links_aweb_and_the_repository() -> None:
    html = _site_html()
    assert '<a href="https://aweb.ai">aweb</a>' in html
    hero = html[html.index('<section class="hero">') : html.index("</section>")]
    assert 'href="https://github.com/awebai/aweb"' in hero
    assert 'href="#quickstart"' in hero
