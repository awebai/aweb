# Secrets change vectors

Regenerate `change-v1.json` from the checked domain models and B2 canonical form:

```sh
cd naapp/secrets
uv run --frozen python scripts/gen_change_vectors.py > vectors/change-v1.json
```

The tests in `tests/test_change_vectors.py` consume these vectors, including B2
minting against PostgreSQL and the actual destination reader.

## D1 pre-deployment re-freeze

For aweb-acgh.43, `destination/1` gains optional `response_max_bytes` in place.
This is a reviewed **pre-deployment optional-field extension**: no Secrets
installation, stored change/1 record, or deployed strict reader exists at this
decision. The coordinator established that deployment condition through the
operator; this exception depends on it.

Every existing case remains byte-identical, including canonical covered bytes
and digests. Regeneration adds the optional field to the destination/1 field
list and appends explicit, omitted-default, ceiling and refusal cases. An
omitted field keeps its existing meaning; no default is inserted into signed
request bytes. This does not make a new field compatible with an older strict
reader.

**After first deployment, any field change to a shape requires a new `v`.**
Re-freezing in place is unavailable once any environment holds those records
or readers. If the pre-deployment condition above is false, this extension
requires `destination/2` instead.
