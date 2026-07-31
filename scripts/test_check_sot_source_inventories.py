from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_sot_source_inventories as inventories


ROOT = Path(__file__).resolve().parents[1]


class SourceInventoryTests(unittest.TestCase):
    def test_current_sot_inventories_match_source(self) -> None:
        self.assertEqual(inventories.check_repository(ROOT), [])

    def test_sql_table_extraction_is_ordered_and_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            migrations = Path(tmp)
            (migrations / "001.sql").write_text(
                "CREATE TABLE IF NOT EXISTS {{tables.alpha}} ();\n"
                "CREATE TABLE {{tables.beta}} ();\n"
            )
            (migrations / "002.sql").write_text(
                "CREATE TABLE IF NOT EXISTS {{tables.alpha}} ();\n"
                "CREATE TABLE IF NOT EXISTS {{tables.gamma}} ();\n"
            )
            (migrations / "003.sql").write_text(
                "DROP TABLE IF EXISTS {{tables.beta}};\n"
            )
            self.assertEqual(
                inventories.extract_sql_tables(migrations),
                ["alpha", "gamma"],
            )

    def test_router_extraction_follows_application_mount_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "api.py"
            source.write_text(
                "app.include_router(alpha_router)\n"
                "app.include_router(\n"
                "    beta_router,\n"
                ")\n"
                "app.mount('/mcp', mcp_app)\n"
            )
            self.assertEqual(inventories.extract_fastapi_routers(source), ["alpha", "beta"])

    def test_cache_fact_extraction_evaluates_source_constants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "registry.py"
            source.write_text(
                "_TEAM_METADATA_CACHE_TTL_SECONDS = 10 * 60\n"
                "_TEAM_REVOCATIONS_CACHE_TTL_SECONDS = 5 * 120\n"
                "_STALE_MULTIPLIER = 2\n"
            )
            self.assertEqual(
                inventories.extract_team_cache_facts(source),
                [
                    "team_metadata_fresh_seconds=600",
                    "team_metadata_stale_seconds=600",
                    "team_revocations_fresh_seconds=600",
                    "team_revocations_stale_seconds=600",
                ],
            )

    def test_negative_control_rejects_source_addition_without_doc_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_root(Path(tmp))
            migration = root / "server/src/aweb/migrations/aweb/002_extra.sql"
            migration.write_text("CREATE TABLE {{tables.beta}} ();\n")
            errors = inventories.check_repository(root)
            self.assertTrue(any("aweb-tables" in error and "beta" in error for error in errors), errors)

    def test_negative_control_rejects_stale_documented_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_root(Path(tmp))
            doc = root / "docs/awid-sot.md"
            doc.write_text(doc.read_text().replace("- `omega`", "- `omega`\n- `deleted_table`"))
            errors = inventories.check_repository(root)
            self.assertTrue(
                any("awid-tables" in error and "deleted_table" in error for error in errors),
                errors,
            )

    def test_negative_control_rejects_cache_ttl_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_root(Path(tmp))
            source = root / "awid/src/awid/registry.py"
            source.write_text(source.read_text().replace("10 * 60", "11 * 60", 1))
            errors = inventories.check_repository(root)
            self.assertTrue(any("aweb-awid-cache" in error and "660" in error for error in errors), errors)

    @staticmethod
    def _fixture_root(root: Path) -> Path:
        paths = [
            "server/src/aweb/migrations/aweb",
            "server/src/aweb",
            "awid/src/awid_service/migrations",
            "awid/src/awid",
            "docs",
        ]
        for path in paths:
            (root / path).mkdir(parents=True, exist_ok=True)
        (root / "server/src/aweb/migrations/aweb/001.sql").write_text(
            "CREATE TABLE IF NOT EXISTS {{tables.alpha}} ();\n"
        )
        (root / "server/src/aweb/api.py").write_text("app.include_router(alpha_router)\n")
        (root / "awid/src/awid_service/migrations/001.sql").write_text(
            "CREATE TABLE IF NOT EXISTS {{tables.omega}} ();\n"
        )
        (root / "awid/src/awid/registry.py").write_text(
            "_TEAM_METADATA_CACHE_TTL_SECONDS = 10 * 60\n"
            "_TEAM_REVOCATIONS_CACHE_TTL_SECONDS = 10 * 60\n"
            "_STALE_MULTIPLIER = 2\n"
        )
        cache_facts = [
            "team_metadata_fresh_seconds=600",
            "team_metadata_stale_seconds=600",
            "team_revocations_fresh_seconds=600",
            "team_revocations_stale_seconds=600",
        ]
        (root / "docs/aweb-sot.md").write_text(
            inventories.render_inventory("aweb-tables", ["alpha"])
            + "\n"
            + inventories.render_inventory("aweb-routers", ["alpha"])
            + "\n"
            + inventories.render_inventory("aweb-awid-cache", cache_facts)
        )
        (root / "docs/awid-sot.md").write_text(
            inventories.render_inventory("awid-tables", ["omega"])
        )
        return root


if __name__ == "__main__":
    unittest.main()
