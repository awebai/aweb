from __future__ import annotations

from pathlib import Path


def _read_sql_files(root: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for path in sorted(root.rglob("*.sql")):
        files.append((path, path.read_text(encoding="utf-8")))
    return files


def test_aweb_migrations_do_not_reference_beadhub_schemas() -> None:
    """Guardrail: keep aweb schema extractable from beadhub.

    The BeadHub schemas live in a separate repo after extraction; aweb must not
    create SQL-level coupling to `server.*` or `beads.*` objects.
    """

    repo_root = Path(__file__).resolve().parents[1]
    aweb_migrations = repo_root / "src" / "aweb" / "migrations"

    for path, content in _read_sql_files(aweb_migrations):
        assert "server." not in content, f"{path} contains a cross-boundary server schema reference"
        assert "beads." not in content, f"{path} contains a cross-boundary beads schema reference"
