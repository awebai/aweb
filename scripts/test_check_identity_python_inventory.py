"""The primitive guard covers source boundaries, not call counts."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

from fixture_repo import init_fixture_repo

spec = importlib.util.spec_from_file_location(
    "guard", Path(__file__).with_name("check_identity_python_inventory.py")
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PrimitiveGuardTests(unittest.TestCase):
    def check(self, file, source, legacy=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            init_fixture_repo(root)
            path = root / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            return guard.check_inventory(root, {"primitive_guard": {"legacy_files": list(legacy)}})

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
                "awid/src/awid/id_certificates.py",
                "from nacl.signing import VerifyKey\ndef verify_ed25519(k,p,s): VerifyKey(k).verify(p,s)\n",
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
        derivation = (
            "from nacl.signing import SigningKey\nfrom awid.did import did_from_public_key\n"
        )
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

    def test_legacy_reason_allows_repeated_uses_without_count_catalog(self):
        source = (
            "from nacl.signing import SigningKey\ndef sign(k,p): return SigningKey(k).sign(p)\n"
        )
        legacy = [
            {"file": "pkg/legacy.py", "reason": "Existing released message signature family."}
        ]
        self.assertEqual(
            [],
            self.check(
                "pkg/legacy.py", source + "def again(k,p): return SigningKey(k).sign(p)\n", legacy
            ),
        )

    def test_legacy_entry_requires_a_reason(self):
        self.assertTrue(self.check("pkg/legacy.py", "", [{"file": "pkg/legacy.py", "reason": ""}]))

    def test_primitive_reference_and_relative_import_are_seen(self):
        for source in [
            "from nacl import signing as s\ncallback = s.VerifyKey\n",
            "from .. import signing\ncallback = signing.verify\n",
        ]:
            calls = guard.scan_python_source(source, module="nacl.child.mod")
            self.assertTrue(calls)

    def test_postponed_key_annotations_do_not_call_a_primitive(self):
        source = (
            "from __future__ import annotations\n"
            "from nacl.signing import SigningKey\n"
            "key: SigningKey\n"
            "def borrow(key: SigningKey | None = None) -> SigningKey:\n"
            "    return key\n"
        )
        self.assertEqual([], self.check("pkg/consumer.py", source))

    def test_postponed_annotations_do_not_hide_runtime_primitive_uses(self):
        prefix = "from __future__ import annotations\nfrom nacl.signing import SigningKey\n"
        for body in (
            "def borrow(key: SigningKey = SigningKey.generate()): return key\n",
            "def borrow(key: SigningKey): return SigningKey(bytes(key))\n",
            "factory: SigningKey = SigningKey\n",
        ):
            with self.subTest(body=body):
                self.assertTrue(self.check("pkg/consumer.py", prefix + body))

    def test_explicitly_evaluated_postponed_annotations_keep_primitive_boundary(self):
        prefix = (
            "from __future__ import annotations\n"
            "from nacl.signing import SigningKey\n"
            "from typing import get_type_hints as resolve\n"
        )
        for body in (
            "def key_type() -> type(SigningKey(bytes(32))): return None\n"
            'resolved_type = resolve(key_type)["return"]\n',
            "def key_type() -> SigningKey: return None\n"
            'factory = resolve(key_type)["return"]\n'
            'signature = factory(bytes(32)).sign(b"annotation-review-control").signature\n',
        ):
            with self.subTest(body=body):
                self.assertTrue(self.check("pkg/consumer.py", prefix + body))

    def test_primitive_constructor_in_a_postponed_annotation_remains_visible(self):
        source = (
            "from __future__ import annotations\n"
            "from nacl.signing import SigningKey\n"
            "def key_type() -> type(SigningKey(bytes(32))): return None\n"
        )
        self.assertTrue(self.check("pkg/consumer.py", source))

    def test_evaluated_annotation_primitive_references_remain_visible(self):
        source = "from nacl.signing import SigningKey\ndef borrow(key: SigningKey): return key\n"
        self.assertTrue(self.check("pkg/consumer.py", source))

    def test_test_files_are_excluded_but_production_test_names_are_not(self):
        source = "from nacl.signing import VerifyKey\ncallback = VerifyKey\n"
        self.assertEqual([], self.check("tests/helper.py", source))
        self.assertTrue(self.check("pkg/src/test_helper.py", source))


if __name__ == "__main__":
    unittest.main()
