from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_hugo_site_scaffold_exists() -> None:
    assert (ROOT / "site" / "hugo.toml").is_file()
    assert (ROOT / "site" / "content" / "_index.md").is_file()
    assert (ROOT / "site" / "layouts" / "index.html").is_file()


def test_hugo_site_mentions_core_awid_promises() -> None:
    html = (ROOT / "site" / "layouts" / "index.html").read_text(encoding="utf-8")
    assert "did:aw" in html
    assert "aw id create" in html
    assert "Signed writes" in html
    assert "elf-host" in html


def _site_html() -> str:
    return (ROOT / "site" / "layouts" / "index.html").read_text(encoding="utf-8")


def test_hugo_site_installs_aw_before_using_it() -> None:
    html = _site_html()
    install = html.index("npm install -g @awebai/aw")
    first_use = min(html.index(command) for command in ("aw init", "aw id create", "aw chat"))
    assert install < first_use


def test_hugo_site_explains_teams_and_naapps_before_the_quickstart() -> None:
    html = _site_html()
    model = html.index('id="model"')
    quickstart = html.index('id="quickstart"')
    assert model < quickstart
    section = html[model:quickstart]
    assert "name:domain" in section
    assert "Native Agentic App (NAAPP)" in section
    assert "aw plugin install" in section
    assert "An independent app can verify public teams today." in section


def test_hugo_site_says_registries_are_federated_through_dns() -> None:
    html = _site_html()
    section = html[html.index('id="federation"') :]
    assert "registry=https://awid.acme.com" in section
    assert "api.awid.ai" in section
    assert "refuses" in section


def test_hugo_site_quickstart_says_where_each_step_runs() -> None:
    html = _site_html()
    quickstart = html[html.index('id="quickstart"') : html.index('id="trust"')]
    assert 'href="https://aweb.ai/docs/cli-tutorial/"' in quickstart
    assert 'data-copy="all"' in quickstart
    for where in ('class="where alice">in alice/', 'class="where bob">in bob/', 'class="where">any directory'):
        assert where in quickstart
    # Copy takes "$ " lines only, so a command must not continue onto another line.
    assert " \\\n" not in quickstart


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
