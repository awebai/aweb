import pytest

from awid_service.testing_templates import _migration_digest


def test_template_digest_tracks_migration_names_and_content(tmp_path):
    first = tmp_path / "001_first.sql"
    first.write_text("SELECT 1;\n")
    modules = (("example", tmp_path),)
    original = _migration_digest(modules)

    first.write_text("SELECT 2;\n")
    edited = _migration_digest(modules)
    assert edited != original

    first.rename(tmp_path / "001_renamed.sql")
    renamed = _migration_digest(modules)
    assert renamed not in {original, edited}

    second = tmp_path / "002_second.sql"
    second.write_text("SELECT 1;\n")
    assert _migration_digest(modules) not in {original, edited, renamed}
    second.unlink()
    assert _migration_digest(modules) == renamed


@pytest.mark.asyncio
async def test_database_clones_are_isolated_and_cleaned_up(awid_database_template):
    template = awid_database_template
    scratch_table = (
        "CREATE TABLE public.a2_probe (id bigint GENERATED ALWAYS AS IDENTITY)"
    )
    advance = "INSERT INTO public.a2_probe DEFAULT VALUES RETURNING id"

    class ProbeFailure(Exception):
        pass

    async with template.clone() as sibling:
        assert await sibling.fetchval("SELECT count(*) FROM awid.schema_migrations") > 0
        with pytest.raises(ProbeFailure):
            async with template.clone() as dirty:
                dirty_name = await dirty.fetchval("SELECT current_database()")
                await dirty.execute(scratch_table)
                assert await dirty.fetchval(advance) == 1
                assert await dirty.fetchval(advance) == 2
                assert (
                    await sibling.fetchval("SELECT to_regclass('public.a2_probe')")
                    is None
                )
                raise ProbeFailure

        assert not await sibling.fetchval(
            "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", dirty_name
        )

        async with template.clone() as fresh:
            assert await fresh.fetchval("SELECT to_regclass('public.a2_probe')") is None
            await fresh.execute(scratch_table)
            assert await fresh.fetchval(advance) == 1
