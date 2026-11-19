# PGDG repository key

`ACCC4CF8.asc` is the unmodified PostgreSQL Debian repository public key from
<https://apt.postgresql.org/pub/repos/apt/ACCC4CF8.asc>, retrieved on 2026-11-13.
Its SHA-256 is
`0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76`.

The primary fingerprint is
`B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`, as published in the
[PostgreSQL Debian installation instructions](https://www.postgresql.org/download/linux/debian/).
The isolated image verifies that this is the only primary key before creating
the keyring scoped to the PGDG apt repository. It does not fetch a signing key
during the build. Updating the trusted key requires a deliberate source change.

The build also runs `test_pgdg_key.py`: the actual Dockerfile key setup must work
with curl returning 18, and another valid key, an appended key and invalid key
material must be refused. The focused check needs Bash and GnuPG, which the
candidate tools image already installs:

```sh
python3 scripts/test-egress/test_pgdg_key.py -v
```
