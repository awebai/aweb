"""The import rewrite from aweb_naapp's contract modules to aweb_naapp_contracts."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from naapp_contracts_rename import rename_file, rename_source


def _rename(source: str) -> str:
    renamed, ambiguous = rename_source(textwrap.dedent(source))
    if ambiguous:
        raise AssertionError(f"unexpected ambiguous references: {ambiguous}")
    return renamed


class ContractModules(unittest.TestCase):
    def test_a_contract_module_import_moves_to_the_contracts_package(self):
        self.assertEqual(
            _rename("from aweb_naapp.manifest import Manifest\n"),
            "from aweb_naapp_contracts.manifest import Manifest\n",
        )

    def test_a_module_whose_name_extends_another_keeps_its_whole_name(self):
        self.assertEqual(
            _rename("from aweb_naapp.manifest_keys import check_manifest_keys\n"),
            "from aweb_naapp_contracts.manifest_keys import check_manifest_keys\n",
        )

    def test_every_contract_module_is_renamed(self):
        for module in (
            "client_identity",
            "did_key",
            "key_file",
            "manifest",
            "manifest_keys",
            "egress",
            "egress.urls",
            "hooks.strictjson",
            "hooks.owner_act",
            "hooks.owner_act_nonces",
            "hooks.catalog",
            "hooks.envelope",
            "hooks.delivery",
        ):
            with self.subTest(module=module):
                self.assertEqual(
                    _rename(f"import aweb_naapp.{module}\n"),
                    f"import aweb_naapp_contracts.{module}\n",
                )

    def test_task_requests_leaves_the_runtime_package(self):
        self.assertEqual(
            _rename("from aweb_naapp.runtime.task_requests import validate_task\n"),
            "from aweb_naapp_contracts.task_requests import validate_task\n",
        )

    def test_runtime_modules_are_left_alone(self):
        source = (
            "from aweb_naapp.hooks.producer import HookProducer\n"
            "from aweb_naapp.hooks.resolver import TeamServerRegistrations\n"
            "from aweb_naapp.runtime.app_credentials import sign_app_credential\n"
            "from aweb_naapp.outbox import StoredEvent\n"
            "from aweb_naapp.chrome import SiteConfig\n"
            "import aweb_naapp\n"
        )
        self.assertEqual(_rename(source), source)

    def test_dotted_names_in_strings_are_renamed(self):
        self.assertEqual(
            _rename('logger = "aweb_naapp.hooks.owner_act_nonces"\n'),
            'logger = "aweb_naapp_contracts.hooks.owner_act_nonces"\n',
        )
        self.assertEqual(
            _rename("probe = 'aweb_naapp.runtime.task_requests'\n"),
            "probe = 'aweb_naapp_contracts.task_requests'\n",
        )

    def test_the_hooks_migration_module_name_is_kept(self):
        source = 'MIGRATIONS_MODULE = "aweb_naapp_hooks"\n'
        self.assertEqual(_rename(source), source)

    def test_the_packaged_catalog_is_read_from_the_contracts_hooks(self):
        self.assertEqual(
            _rename('data = files("aweb_naapp.hooks").joinpath("catalog-v1.json")\n'),
            'data = files("aweb_naapp_contracts.hooks").joinpath("catalog-v1.json")\n',
        )


class NamesImportedFromAPackage(unittest.TestCase):
    def test_contract_names_are_split_from_runtime_names_at_the_root(self):
        self.assertEqual(
            _rename("from aweb_naapp import llms, manifest\n"),
            "from aweb_naapp import llms\nfrom aweb_naapp_contracts import manifest\n",
        )

    def test_an_alias_is_kept(self):
        self.assertEqual(
            _rename("from aweb_naapp import manifest as manifest_module\n"),
            "from aweb_naapp_contracts import manifest as manifest_module\n",
        )

    def test_contract_hooks_are_split_from_runtime_hooks(self):
        self.assertEqual(
            _rename("from aweb_naapp.hooks import envelope, producer\n"),
            "from aweb_naapp.hooks import producer\nfrom aweb_naapp_contracts.hooks import envelope\n",
        )

    def test_task_requests_is_split_from_runtime_modules(self):
        self.assertEqual(
            _rename("from aweb_naapp.runtime import task_requests, team_auth\n"),
            "from aweb_naapp.runtime import team_auth\nfrom aweb_naapp_contracts import task_requests\n",
        )

    def test_a_runtime_only_import_from_a_package_is_left_alone(self):
        source = "from aweb_naapp import CSS_SHA256, aweb_css\n"
        self.assertEqual(_rename(source), source)

    def test_a_parenthesised_import_keeps_its_indent_and_wraps_when_long(self):
        source = """\
        def probe():
            from aweb_naapp import (
                llms,
                manifest,
                reference_page_for_a_very_long_name_indeed_so_that_the_line_wraps_past_one_hundred,
            )
        """
        self.assertEqual(
            _rename(source),
            textwrap.dedent(
                """\
                def probe():
                    from aweb_naapp import (
                        llms,
                        reference_page_for_a_very_long_name_indeed_so_that_the_line_wraps_past_one_hundred,
                    )
                    from aweb_naapp_contracts import manifest
                """
            ),
        )


class ContractTestSupport(unittest.TestCase):
    def test_contract_test_modules_move_to_the_contracts_testing_package(self):
        for module in ("network", "production_registry", "team_facts", "human_members"):
            with self.subTest(module=module):
                self.assertEqual(
                    _rename(f"from aweb_naapp_testing.{module} import thing\n"),
                    f"from aweb_naapp_contracts_testing.{module} import thing\n",
                )

    def test_the_root_names_move_with_the_root(self):
        self.assertEqual(
            _rename("from aweb_naapp_testing import REGISTRY_URL, Member, did_key\n"),
            "from aweb_naapp_contracts_testing import REGISTRY_URL, Member, did_key\n",
        )

    def test_runtime_test_support_is_left_alone(self):
        source = (
            "from aweb_naapp_testing.owner_acts import TeamOwner\n"
            "from aweb_naapp_testing.webauthn import SoftAuthenticator\n"
            'pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")\n'
        )
        self.assertEqual(_rename(source), source)

    def test_a_root_import_naming_a_runtime_module_is_split(self):
        self.assertEqual(
            _rename("from aweb_naapp_testing import Member, owner_acts\n"),
            "from aweb_naapp_testing import owner_acts\n"
            "from aweb_naapp_contracts_testing import Member\n",
        )

    def test_the_bare_testing_package_is_reported(self):
        source = "import aweb_naapp_testing\n"
        renamed, ambiguous = rename_source(source)
        self.assertEqual(renamed, source)
        self.assertEqual(ambiguous, [(1, "aweb_naapp_testing")])


class AmbiguousReferences(unittest.TestCase):
    def test_the_bare_hooks_package_is_reported_not_guessed(self):
        source = "import aweb_naapp.hooks\n"
        renamed, ambiguous = rename_source(source)
        self.assertEqual(renamed, source)
        self.assertEqual(ambiguous, [(1, "aweb_naapp.hooks")])

    def test_an_import_of_a_contract_module_inside_a_string_is_reported(self):
        source = 'probe = "from aweb_naapp.hooks import catalog\\n"\n'
        renamed, ambiguous = rename_source(source)
        self.assertEqual(renamed, source)
        self.assertEqual(ambiguous, [(1, "from aweb_naapp.hooks import catalog")])

    def test_an_import_of_runtime_modules_inside_a_string_is_left_alone(self):
        source = 'probe = "from aweb_naapp.hooks import producer"\n'
        self.assertEqual(_rename(source), source)

    def test_an_import_with_a_comment_inside_is_reported_not_rewritten(self):
        source = "from aweb_naapp import (  # docs and contracts\n    llms,\n    manifest,\n)\n"
        renamed, ambiguous = rename_source(source)
        self.assertEqual(renamed, source)
        self.assertEqual(ambiguous, [(1, "from aweb_naapp import (comment inside)")])


class Files(unittest.TestCase):
    def test_rewriting_twice_changes_nothing_the_second_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "module.py"
            path.write_text("from aweb_naapp import llms, manifest\nimport aweb_naapp.egress\n")
            self.assertTrue(rename_file(path).changed)
            once = path.read_text()
            self.assertFalse(rename_file(path).changed)
            self.assertEqual(path.read_text(), once)


if __name__ == "__main__":
    unittest.main()
