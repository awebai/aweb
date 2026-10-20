from __future__ import annotations

from pathlib import Path

import pytest

from aweb_naapp.robots import robots_txt
from aweb_naapp.skills import Skills

_ENV = "EXAMPLE_SKILLS_DIR"


def _write_skill(root: Path, name: str, text: str = "# skill\n") -> None:
    (root / name).mkdir(parents=True)
    (root / name / "SKILL.md").write_text(text, encoding="utf-8")


@pytest.fixture
def skills_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv(_ENV, raising=False)
    root = tmp_path / "skills"
    _write_skill(root, "beta", "# Beta\n")
    _write_skill(root, "alpha", "# Alpha\n")
    return root


def _skills(source: Path, container: Path | None = None) -> Skills:
    return Skills(
        app_name="example",
        env_var=_ENV,
        source_dir=source,
        container_dir=container or source.parent / "no-container",
    )


def test_names_are_sorted_and_read_returns_the_skill(skills_root: Path) -> None:
    skills = _skills(skills_root)
    assert skills.names() == ["alpha", "beta"]
    assert skills.read("alpha") == "# Alpha\n"
    assert skills.read("missing") is None


def test_index_lists_every_skill_route_for_the_app(skills_root: Path) -> None:
    index = _skills(skills_root).index()
    assert index.startswith("# example agent skills\n")
    assert "- GET /skills/alpha/SKILL.md\n" in index
    assert "- GET /skills/beta/SKILL.md\n" in index


def test_configured_directory_wins(skills_root: Path, tmp_path: Path, monkeypatch) -> None:
    configured = tmp_path / "configured"
    _write_skill(configured, "gamma")
    monkeypatch.setenv(_ENV, str(configured))
    assert _skills(skills_root).names() == ["gamma"]


def test_container_directory_is_the_fallback_for_an_installed_package(
    skills_root: Path, tmp_path: Path
) -> None:
    skills = _skills(tmp_path / "site-packages" / "skills", container=skills_root)
    assert skills.names() == ["alpha", "beta"]


def test_no_directory_means_no_skills(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(_ENV, raising=False)
    skills = _skills(tmp_path / "absent")
    assert skills.names() == []
    assert skills.read("alpha") is None


@pytest.mark.parametrize("name", ["../alpha", "Alpha", "", "a/b", "-x", "a" * 82])
def test_names_outside_the_skill_pattern_are_never_read(skills_root: Path, name: str) -> None:
    assert _skills(skills_root).read(name) is None


def test_symlinked_skills_are_never_served(skills_root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-secret.md"
    outside.write_text("secret outside skill root", encoding="utf-8")
    (skills_root / "leak").mkdir()
    (skills_root / "leak" / "SKILL.md").symlink_to(outside)
    elsewhere = tmp_path / "elsewhere"
    _write_skill(elsewhere, "linked")
    (skills_root / "linked").symlink_to(elsewhere / "linked")

    skills = _skills(skills_root)
    assert skills.names() == ["alpha", "beta"]
    assert skills.read("leak") is None
    assert skills.read("linked") is None


def test_robots_allows_everything_without_rules() -> None:
    assert robots_txt() == "User-agent: *\nAllow: /\n"


def test_robots_disallows_each_given_path() -> None:
    assert robots_txt(disallow=("/present/", "/assets/")) == (
        "User-agent: *\nDisallow: /present/\nDisallow: /assets/\n"
    )
