# Legacy owner cutover data

The checked-in JSON captures the genuine pre-cutover `OwnerConsole.apply_owner_act`
and B3 registration path. Each file records its source SHA and generation command.
`generate.py` is a deliberate capture tool, not a test-time migration helper; it
refuses to run once the cutover migration exists. Ordinary tests never run a Git
checkout or a legacy writer to construct these rows.

Capture runs require an assigned private PostgreSQL fixture and the suite/load
guard. From `naapp/secrets` at the recorded pre-cutover head, the generator command
is:

```sh
OWNER_CUTOVER_WRITE_FIXTURES=1 uv run --frozen --no-sync --with pytest-xdist pytest -n 2 --dist loadscope --assert=plain -q tests/fixtures/owner_holding_cutover/generate.py
```

Only public database material is retained: credential public keys, historical
signed authorizations and signed answers to genuine outstanding LOGIN challenges.
No authenticator private key or plaintext enrolment token is captured. Migration
tests load the data before the cutover; ephemeral LOGIN challenge expiry is made
relative to the test, preserving the original signed challenge and assertion.
The original role-assignment timestamps, scopes, subjects and credentials remain
unchanged. These are migration/component controls, not supported bootstrap proof.
