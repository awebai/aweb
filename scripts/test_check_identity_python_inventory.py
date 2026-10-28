"""The inventory must reject new calls, not merely recognize a listed file."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest


MODULE = Path(__file__).with_name("check_identity_python_inventory.py")
SPEC = importlib.util.spec_from_file_location("identity_python_inventory", MODULE)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PythonIdentityInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True, capture_output=True)
        self.file = "awid/src/awid/signing.py"
        self.path = self.root / self.file
        self.path.parent.mkdir(parents=True)
        self.path.write_text("def checked(key, data, signature):\n    key.verify(data, signature)\n")
        self.inventory = {
            "v": 1,
            "sites": [{"id": "PY.VERIFY", "repo": "aweb", "files": [self.file],
                       "sites": [{"file": self.file, "symbol": "checked"}],
                       "ed25519_profile": "legacy"}],
            "python_guard": {"v": 1, "sites": [
                {"row": "PY.VERIFY", "file": self.file, "symbol": "checked",
                 "calls": {"key.verify": 1}}]},
        }

    def errors(self, inventory=None):
        return GUARD.check_inventory(self.root, inventory or self.inventory)

    def test_exact_function_and_call_pass(self):
        self.assertEqual(self.errors(), [])

    def test_new_function_in_an_already_listed_file_refuses(self):
        with self.path.open("a") as f:
            f.write("\ndef bypass(key, data, signature):\n    key.verify(data, signature)\n")
        self.assertTrue(any("bypass" in e and "unlisted" in e for e in self.errors()))

    def test_extra_primitive_in_an_already_listed_function_refuses(self):
        with self.path.open("a") as f:
            f.write("    key.verify(data, signature)\n")
        self.assertTrue(any("call counts" in e for e in self.errors()))

    def test_removed_call_leaves_a_stale_entry(self):
        self.path.write_text("def checked(*args):\n    return True\n")
        self.assertTrue(any("stale" in e for e in self.errors()))

    def test_new_source_file_is_scanned_without_an_inventory_file_entry(self):
        other = self.path.with_name("new_verifier.py")
        other.write_text("from nacl.signing import VerifyKey as V\ndef new(key):\n    return V(key)\n")
        self.assertTrue(any("new_verifier.py" in e and "unlisted" in e for e in self.errors()))

    def test_app_and_secrets_runner_sources_are_scanned(self):
        for file in ("naapp/new-app/src/principal.py", "naapp/secrets/runner/src/protocol.py"):
            with self.subTest(file=file):
                path = self.root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def check(k,m,s):\n    k.verify(m,s)\n")
                self.assertTrue(any(file in e and "unlisted" in e for e in self.errors()))

    def test_raw_libsodium_alias_is_seen(self):
        calls = GUARD.scan_python_source(
            "from nacl.bindings import crypto_sign_open as open_signature\n"
            "def check(s,k):\n    return open_signature(s,k)\n")
        self.assertEqual(dict(calls["check"]), {"nacl.bindings.crypto_sign_open": 1})

    def test_protocol_sign_and_verify_wrappers_are_seen_at_consumers(self):
        calls = GUARD.scan_python_source(
            "from aweb_secrets.runner_protocol import sign_assignment, verify_request_signature\n"
            "def run(k):\n    sign_assignment(k)\n    verify_request_signature(k)\n")
        self.assertEqual(dict(calls["run"]), {
            "aweb_secrets.runner_protocol.sign_assignment": 1,
            "aweb_secrets.runner_protocol.verify_request_signature": 1})

    def test_import_alias_and_chained_constructor_are_resolved(self):
        source = "from nacl.signing import VerifyKey as V\ndef check(k,m,s):\n    V(k).verify(m,s)\n"
        calls = GUARD.scan_python_source(source)
        self.assertEqual(dict(calls["check"]), {
            "nacl.signing.VerifyKey": 1, "nacl.signing.VerifyKey().verify": 1})

    def test_module_alias_and_ed25519_key_generation_are_seen(self):
        calls = GUARD.scan_python_source(
            "import nacl.signing as s\n"
            "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K\n"
            "def mint():\n    return s.SigningKey.generate(), K.generate()\n")
        self.assertEqual(dict(calls["mint"]), {
            "nacl.signing.SigningKey.generate": 1,
            "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate": 1})

    def test_did_literals_are_seen_even_in_validation(self):
        calls = GUARD.scan_python_source(
            'def mint(k):\n    return "did:key:z" + k\n'
            'def validate(k):\n    return k.startswith("did:key:")\n')
        self.assertEqual(dict(calls["mint"]), {"literal:did:key": 1})
        self.assertEqual(dict(calls["validate"]), {"literal:did:key": 1})

    def test_relative_imports_resolve_against_the_source_package(self):
        calls = GUARD.scan_python_source(
            "from .signing import verify_did_key_signature\nfrom . import did\n"
            "def use(k):\n    verify_did_key_signature(k)\n    did.did_from_public_key(k)\n",
            module="awid.ratelimit")
        self.assertEqual(dict(calls["use"]), {
            "awid.signing.verify_did_key_signature": 1, "awid.did.did_from_public_key": 1})

    def test_primitive_aliases_callbacks_and_partial_loads_are_recorded(self):
        calls = GUARD.scan_python_source(
            "from awid.id_certificates import verify_id_chain\nfrom nacl.signing import VerifyKey\n"
            "def use(callback):\n    check = verify_id_chain\n    callback(VerifyKey)\n")
        self.assertEqual(dict(calls["use"]), {
            "reference:awid.id_certificates.verify_id_chain": 1,
            "reference:nacl.signing.VerifyKey": 1})

    def test_primitive_wildcard_imports_refuse_including_relative_form(self):
        for source in ("from nacl.bindings import *", "from .did import *"):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "wildcard import"):
                GUARD.scan_python_source(source, module="awid.consumer")

    def test_test_named_production_modules_are_not_excluded(self):
        for file in ("new-package/src/pkg/test_production.py", "new-package/src/pkg/test/consumer.py",
                     "new-package/src/pkg/conftest.py"):
            with self.subTest(file=file):
                path = self.root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def check(k,m,s):\n    k.verify(m,s)\n")
                self.assertTrue(any(file in e and "unlisted" in e for e in self.errors()))
                path.unlink()

    def test_explicit_source_tests_directory_is_excluded(self):
        path = self.root / "new-package/src/pkg/tests/check.py"
        path.parent.mkdir(parents=True)
        path.write_text("def check(k,m,s):\n    k.verify(m,s)\n")
        self.assertEqual(self.errors(), [])

    def test_docstrings_do_not_add_did_literal_sites(self):
        self.assertEqual(GUARD.scan_python_source('"""did:key:example"""\ndef f():\n    """did:aw:example"""\n'), {})

    def test_all_nine_security_review_probes_are_detected(self):
        probes = [
            ("awid/src/awid/id_certificates.py", "from nacl.signing import VerifyKey\ndef zz(k,m,s):\n    VerifyKey(k).verify(m,s)\n"),
            ("awid/src/awid/id_certificates.py", "from nacl.bindings import crypto_sign_open\ndef zz(k,m,s):\n    crypto_sign_open(s+m,k)\n"),
            ("server/src/aweb/api.py", "import nacl.bindings as b\ndef zz(k,m,s):\n    b.crypto_sign_verify_detached(s,m,k)\n"),
            ("awid/src/awid/ratelimit.py", "from .signing import verify_did_key_signature\ndef zz(k):\n    verify_did_key_signature(k)\n"),
            ("awid/src/awid/ratelimit.py", "from . import did\ndef zz(k):\n    did.did_from_public_key(k)\n"),
            ("awid/src/awid/ratelimit.py", '_ZZ_PREFIX = "did:key:z"\ndef zz(k):\n    return _ZZ_PREFIX+k\n'),
            ("awid/src/awid/ratelimit.py", 'def zz(k):\n    return "did:key:z{}".format(k)\n'),
            ("awid/src/awid/ratelimit.py", "from awid.id_certificates import verify_id_chain\ndef zz(k):\n    check=verify_id_chain\n    return check(k)\n"),
            ("naapp/logs/src/aweb_logs/zz_probe.py", "from nacl.signing import VerifyKey\ndef zz(k,m,s):\n    VerifyKey(k).verify(m,s)\n"),
        ]
        for file, source in probes:
            with self.subTest(file=file, source=source):
                path = self.root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
                self.assertTrue(any(file in e and "unlisted" in e for e in self.errors()))
                path.unlink()

    def test_class_and_nested_function_have_distinct_symbols(self):
        calls = GUARD.scan_python_source(
            "class Verifier:\n    def run(self,k,m,s):\n"
            "        def nested():\n            k.verify(m,s)\n"
            "        k.verify(m,s)\n")
        self.assertEqual(set(calls), {"Verifier.run", "Verifier.run.nested"})

    def test_row_mapping_does_not_implicitly_cover_every_function(self):
        bad = copy.deepcopy(self.inventory)
        bad["sites"][0]["sites"] = []
        self.assertTrue(any("exact site" in e for e in self.errors(bad)))

    def test_duplicate_catalog_entry_refuses(self):
        bad = copy.deepcopy(self.inventory)
        bad["python_guard"]["sites"] *= 2
        self.assertTrue(any("duplicate" in e for e in self.errors(bad)))

    def test_strict_id_module_cannot_add_a_raw_verifier_helper(self):
        self.file = "awid/src/awid/id_certificates.py"
        self.path = self.root / self.file
        self.path.write_text("def bypass(k,m,s):\n    k.verify(m,s)\n")
        # Listing the bypass as strict must not excuse skipping the shared gate.
        row = self.inventory["sites"][0]
        row.update(files=[self.file], sites=[{"file": self.file, "symbol": "bypass"}],
                   ed25519_profile="strict")
        self.inventory["python_guard"]["sites"] = [
            {"row": row["id"], "file": self.file, "symbol": "bypass", "calls": {"k.verify": 1}}]
        (self.root / "awid/src/awid/signing.py").unlink()
        self.assertTrue(any("shared strict verifier" in e for e in self.errors()))

    def test_metadata_cannot_downgrade_the_strict_module(self):
        self.file = "awid/src/awid/id_certificates.py"
        self.path = self.root / self.file
        self.path.write_text("def verify_id_certificate(k,m,s):\n    k.verify(m,s)\n")
        row = self.inventory["sites"][0]
        row.update(files=[self.file], sites=[{"file": self.file, "symbol": "verify_id_certificate"}])
        self.inventory["python_guard"]["sites"] = [
            {"row": row["id"], "file": self.file, "symbol": "verify_id_certificate", "calls": {"k.verify": 1}}]
        (self.root / "awid/src/awid/signing.py").unlink()
        self.assertTrue(any("strict profile" in e for e in self.errors()))

    def test_strict_consumer_cannot_use_a_legacy_crypto_wrapper(self):
        self.path.write_text("from awid.signing import verify_signature as unchecked\n"
                             "def checked(k,m,s):\n    return unchecked(k,m,s)\n")
        self.inventory["sites"][0]["ed25519_profile"] = "strict"
        self.inventory["python_guard"]["sites"][0]["calls"] = {"awid.signing.verify_signature": 1}
        self.assertTrue(any("shared strict verifier" in e for e in self.errors()))

    def test_strict_consumer_cannot_use_even_a_listed_raw_libsodium_verifier(self):
        self.path.write_text("from nacl.bindings import crypto_sign_open\n"
                             "def checked(k,m,s):\n    return crypto_sign_open(s+m,k)\n")
        self.inventory["sites"][0]["ed25519_profile"] = "strict"
        self.inventory["python_guard"]["sites"][0]["calls"] = {"nacl.bindings.crypto_sign_open": 1}
        self.assertTrue(any("shared strict verifier" in e for e in self.errors()))

    def test_comments_and_strings_are_not_calls(self):
        self.assertEqual(GUARD.scan_python_source('# k.verify(m,s)\ntext = "k.verify(m,s)"\n'), {})

    def test_boolean_call_count_is_not_an_integer_count(self):
        bad = copy.deepcopy(self.inventory)
        bad["python_guard"]["sites"][0]["calls"]["key.verify"] = True
        self.assertTrue(any("positive integers" in e for e in self.errors(bad)))


if __name__ == "__main__":
    unittest.main()
