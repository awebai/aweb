# aweb secrets values

The sole structured credential codec used by custody and the runner. Runtime
imports use only the Python standard library. `CAPTURE_FIELDS` defines each
kind's required and optional fields; `encode_value` and `decode_value` validate
the whole mapping. `ValueInvalid` carries a fixed message without the value.

Custody and operation modules re-export these same objects. Moving them here
does not change the encoded bytes, field validation or supported kinds.

```sh
uv run pytest tests/test_values.py
uv run ruff check src tests
uv run mypy src
```

NUL refusal for process delivery and selecting a declared field belong to the
runner boundary. The codec does not decide a caller's authority or destination.

`aweb_secrets_values.redaction.KnownValues` and
`aweb_secrets_values.credential_shapes` provide the same known-value encoding
redaction, partial-tail handling and credential tripwire used by the app. The
app re-exports these objects too. They perform no I/O, grant no authority and
do not replace the caller's output bounds or projection policy.
