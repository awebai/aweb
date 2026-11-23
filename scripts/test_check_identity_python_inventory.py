"""The Python guard matches each reviewed exemption to one real call."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

from fixture_repo import init_fixture_repo

spec = importlib.util.spec_from_file_location(
    "guard", Path(__file__).with_name("check_identity_python_inventory.py")
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PrimitiveGuardTests(unittest.TestCase):
    def check(self, file, source, exemptions=(), creation_paths=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            init_fixture_repo(root)
            path = root / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            return guard.check_inventory(
                root,
                {
                    "creation_paths": creation_paths,
                    "primitive_guard": {"exempt_calls": list(exemptions)},
                },
            )

    def test_new_raw_crypto_is_refused(self):
        errors = self.check(
            "pkg/consumer.py",
            "from nacl.signing import VerifyKey as Key\ndef check(k, p, s): Key(k).verify(p, s)\n",
        )
        self.assertTrue(any("shared verifier" in e for e in errors), errors)

    def test_shared_verifier_and_neighboring_public_call(self):
        self.assertEqual(
            [],
            self.check(
                "awid/src/awid/signature_wire.py",
                "from nacl.signing import VerifyKey\ndef verify_bytes(k,p,s): VerifyKey(k).verify(p,s)\n",
            ),
        )
        self.assertEqual(
            [],
            self.check(
                "pkg/consumer.py",
                "from awid.id_certificates import verify_ed25519\ndef check(k,p,s): verify_ed25519(k,p,s)\n",
            ),
        )
        errors = self.check(
            "awid/src/awid/id_certificates.py",
            "from nacl.signing import VerifyKey\ndef bypass(k,p,s): VerifyKey(k).verify(p,s)\n",
        )
        self.assertTrue(errors)

    def test_seed_did_key_derivation_is_one_shared_site(self):
        derivation = "from nacl.signing import SigningKey\nfrom awid.did import did_from_public_key\n"
        shared = (
            derivation
            + "def did_key_from_signing_key(seed): return did_from_public_key(bytes(SigningKey(seed).verify_key))\n"
        )
        self.assertEqual([], self.check("awid/src/awid/did.py", shared))
        self.assertEqual(
            [],
            self.check(
                "pkg/consumer.py",
                "from awid.did import did_key_from_signing_key\ndef did(seed): return did_key_from_signing_key(seed)\n",
            ),
        )
        raw = (
            derivation
            + "def did(seed): return did_from_public_key(bytes(SigningKey(seed).verify_key))\n"
        )
        errors = self.check("pkg/consumer.py", raw)
        self.assertTrue(any("shared verifier" in e for e in errors), errors)

    def test_exemption_needs_exactly_one_call(self):
        file = "pkg/legacy.py"
        source = "from nacl.signing import SigningKey\ndef make(seed): return SigningKey(seed)\n"
        exemption = {
            "file": file,
            "symbol": "make",
            "callee": "nacl.signing.SigningKey",
            "reason": "Restores a typed signing key for the independent fixture.",
        }
        self.assertEqual([], self.check(file, source, [exemption]))
        repeated = source.replace(
            "return SigningKey(seed)", "return SigningKey(seed), SigningKey(seed)"
        )
        cases = [
            (source, [exemption, exemption], "duplicate primitive exemption"),
            (
                source.replace("def make", "def moved"),
                [exemption],
                "unused primitive exemption",
            ),
            (repeated, [exemption], "matches 2 calls"),
            (
                source,
                [{**exemption, "reason": " "}],
                "requires file, symbol, callee and reason",
            ),
            (
                source,
                [{**exemption, "file": "pkg/missing.py"}],
                "listed source file pkg/missing.py is missing",
            ),
            (
                source,
                [{**exemption, "callee": "reference:nacl.signing.SigningKey"}],
                "must name a call",
            ),
        ]
        for fixture, exemptions, expected in cases:
            with self.subTest(expected=expected):
                errors = self.check(file, fixture, exemptions)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_named_call_does_not_allow_a_neighboring_symbol_or_reference(self):
        file = "pkg/legacy.py"
        source = """from nacl.signing import SigningKey
def make(seed): return SigningKey(seed)
def neighbor(seed): return SigningKey(seed)
def reference(): return SigningKey
"""
        exemption = {
            "file": file,
            "symbol": "make",
            "callee": "nacl.signing.SigningKey",
            "reason": "Restores a typed signing key for the independent fixture.",
        }
        errors = self.check(file, source, [exemption])
        self.assertEqual(2, len(errors), errors)
        self.assertTrue(any(":neighbor:" in error for error in errors), errors)
        self.assertTrue(
            any(":reference:reference:" in error for error in errors), errors
        )

    def test_local_creation_path_must_exist(self):
        errors = self.check(
            "pkg/existing.py",
            "",
            creation_paths=[{"repo": "aweb", "files": ["pkg/deleted.py"]}],
        )
        self.assertTrue(
            any("pkg/deleted.py is missing" in error for error in errors), errors
        )

    def test_typed_key_helpers_and_parameters_resolve_to_raw_calls(self):
        source = """
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as Public
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Private
def public_key(k) -> Public: return Public.from_public_bytes(k)
def verify_assignment(k, signature, payload): public_key(k).verify(signature, payload)
def sign_request(k: Private, payload):
    selected = k
    return selected.sign(payload)
"""
        calls = guard.scan_python_source(source)
        prefix = "cryptography.hazmat.primitives.asymmetric.ed25519."
        self.assertEqual(
            {prefix + "Ed25519PublicKey.verify": 1}, calls["verify_assignment"]
        )
        self.assertEqual({prefix + "Ed25519PrivateKey.sign": 1}, calls["sign_request"])

    def test_typed_instance_attributes_resolve_to_raw_signs(self):
        for fields in (
            "    key: Key",
            "    def __init__(self, key: Key): self.key = key",
            "    def __init__(self, seed): self.key = Key(seed)",
        ):
            source = f"""from nacl.signing import SigningKey as Key
class Owner:
    def sign(self, message): return self.key.sign(message)
{fields}
"""
            with self.subTest(fields=fields):
                errors = self.check("pkg/consumer.py", source)
                self.assertTrue(
                    any(
                        "Owner.sign:nacl.signing.SigningKey.sign" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_verify_key_projection_is_detected_on_keys(self):
        source = """from nacl.signing import SigningKey as Key
from awid.did import did_from_public_key
def key_from_file() -> Key: ...
class Owner:
    key: Key
    def did(self): return did_from_public_key(bytes(self.key.verify_key))
def from_helper(): return did_from_public_key(bytes(key_from_file().verify_key))
def from_parameter(key: Key): return did_from_public_key(bytes(key.verify_key))
def verify(key: Key, payload, sig): return key.verify_key.verify(payload, sig)
def with_non_key(config): return config.verify_key
"""
        calls = guard.scan_python_source(source)
        projection = "reference:nacl.signing.SigningKey.verify_key"
        for symbol in ("Owner.did", "from_helper", "from_parameter", "verify"):
            with self.subTest(symbol=symbol):
                self.assertEqual(1, calls.get(symbol, {}).get(projection, 0), calls)
        self.assertEqual(
            1, calls.get("verify", {}).get("nacl.signing.VerifyKey.verify", 0)
        )
        self.assertNotIn("with_non_key", calls)

    def test_primitive_reference_and_relative_import_are_seen(self):
        for source in [
            "from nacl import signing as s\ncallback = s.VerifyKey\n",
            "from .. import signing\ncallback = signing.verify\n",
        ]:
            calls = guard.scan_python_source(source, module="nacl.child.mod")
            self.assertTrue(calls)

    def test_test_files_are_excluded_but_production_test_names_are_not(self):
        source = "from nacl.signing import VerifyKey\ncallback = VerifyKey\n"
        self.assertEqual([], self.check("tests/helper.py", source))
        self.assertTrue(self.check("pkg/src/test_helper.py", source))


if __name__ == "__main__":
    unittest.main()
