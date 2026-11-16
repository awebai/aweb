from pathlib import Path
import tempfile
import unittest

from check_retired_protection import violations


class RetiredProtectionGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def test_resurrected_module_fails_even_without_a_known_name(self):
        name = "awid/src/awid/protected_membership.py"
        self.write(name, "# empty resurrection\n")
        self.assertIn("removed path exists", violations(self.root, [name])[0])

    def test_new_import_definition_and_wire_field_are_refused(self):
        for content in (
            "from old import observe_team_protection\n",
            "def record_applied(tx): pass\n",
            '{"team_protection": true}\n',
            'HEADER = "X-AWEB-Protected-Effect"\n',
        ):
            with self.subTest(content=content):
                self.write("server/new.py", content)
                self.assertTrue(violations(self.root, ["server/new.py"]))

    def test_surviving_passkey_request_custody_and_freshness_are_allowed(self):
        self.write("server/kept.py", """
from awid.protected_request import verify_protected_request
from approval import VerifiedProtectedEffect
def require_fresh(): pass
class EncryptionCustody: pass
""")
        self.assertEqual(violations(self.root, ["server/kept.py"]), [])

    def test_archived_and_forward_sql_are_explicit_exceptions_only(self):
        allowed = "awid/src/awid_service/migrations/016_drop_retired_team_protection.sql"
        body = "DROP TABLE IF EXISTS {{tables.team_protection}};\n"
        self.write(allowed, body)
        self.assertEqual(violations(self.root, [allowed]), [])
        self.write("awid/src/awid_service/migrations/999_new.sql", body)
        self.assertTrue(violations(self.root, ["awid/src/awid_service/migrations/999_new.sql"]))


if __name__ == "__main__":
    unittest.main()
