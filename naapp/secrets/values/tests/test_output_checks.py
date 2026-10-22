"""Shared output checks stay usable without the app or a database."""

import base64
import subprocess
import sys

from aweb_secrets_values.credential_shapes import has_credential_shape
from aweb_secrets_values.redaction import KnownValues


def test_same_known_value_encodings_and_partial_tail_checks():
    known = KnownValues()
    known.add_basic("fixture", "user", "fixture-password")
    encoded = base64.b64encode(b"user:fixture-password")
    assert known.redact(encoded) == (b"[REDACTED:fixture]", 1)
    assert known.redact_tail(b"prefix fixture-pass") == (b"prefix [REDACTED:fixture]", 1)


def test_shape_detection_remains_independent_of_known_values():
    assert has_credential_shape(b'{"password":"undeclared-fixture"}')
    assert not has_credential_shape(b'{"message":"finished"}')


def test_output_check_runtime_imports_are_standalone():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from aweb_secrets_values.redaction import KnownValues; "
            "from aweb_secrets_values.credential_shapes import has_credential_shape; "
            "assert not any(k.startswith(('aweb_naapp','aweb_secrets.','awid','pgdbm')) for k in sys.modules)",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
