"""Library builds and tests against the awid and naapp-lib of the checkout it lives in."""

from __future__ import annotations

from pathlib import Path

_LIBRARY_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _LIBRARY_ROOT.parents[1]


def _imported_from(module_file: str | None, source: Path) -> bool:
    assert module_file is not None
    return Path(module_file).resolve().is_relative_to(source.resolve())


def test_aweb_naapp_imports_from_this_checkouts_naapp_lib() -> None:
    import aweb_naapp

    source = _REPO_ROOT / "naapp-lib" / "src"
    assert _imported_from(aweb_naapp.__file__, source), (
        f"aweb_naapp was imported from {aweb_naapp.__file__}, not from {source}"
    )


def test_awid_imports_from_this_checkouts_awid() -> None:
    import awid

    source = _REPO_ROOT / "awid" / "src"
    assert _imported_from(awid.__file__, source), f"awid was imported from {awid.__file__}, not from {source}"


def test_the_lock_fetches_no_dependency_from_git() -> None:
    lock = (_LIBRARY_ROOT / "uv.lock").read_text(encoding="utf-8")
    git_sources = [line.strip() for line in lock.splitlines() if "source = { git" in line]
    assert not git_sources, "library's lock fetches from git:\n  " + "\n  ".join(git_sources)


def test_the_source_check_rejects_a_module_from_elsewhere(tmp_path: Path) -> None:
    source = tmp_path / "naapp-lib" / "src"
    inside = source / "aweb_naapp" / "__init__.py"
    outside = tmp_path / "site-packages" / "aweb_naapp" / "__init__.py"
    for path in (inside, outside):
        path.parent.mkdir(parents=True)
        path.write_text("")

    assert _imported_from(str(inside), source)
    assert not _imported_from(str(outside), source)
