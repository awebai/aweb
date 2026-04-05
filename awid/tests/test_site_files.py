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
