# Hosted namespace controller database alignment

This is the one-time AWID half of the hosted `*.aweb.ai` controller alignment.
It scans the complete active AWID child universe, requires exactly 201 active,
verified, canonical direct children, and requires all 201 to be in the reviewed
223-domain AC manifest with their exact old controller. The other 22 manifest
domains must be absent from AWID. It changes only
`awid.dns_namespaces.controller_did` for those exact 201 rows. It never inserts
or deletes rows and does not change status, timestamps, IDs, addresses, teams,
origins, or history.

Run from `awid/` with the production database URL supplied only through the
environment. Keep the canonical manifest bytes unchanged after review. Every
command requires their exact SHA-256, expected count, and parent controller DID:

```bash
export AWID_DATABASE_URL='postgresql://...'
MANIFEST=/secure/alignment-manifest.json
MANIFEST_SHA256='<reviewed lowercase sha256>'
PARENT_DID='<reviewed did:key controller of aweb.ai>'
BACKUP=/secure/awid-dns-namespaces-before.json

uv run python scripts/align_hosted_namespace_controllers_db.py \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --expected-count 223 --expected-present-count 201 \
  --expected-parent-controller-did "$PARENT_DID"

uv run python scripts/align_hosted_namespace_controllers_db.py backup \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --expected-count 223 --expected-present-count 201 \
  --expected-parent-controller-did "$PARENT_DID" \
  --backup "$BACKUP"

# Set this only after preserving and reviewing the backup command's reported digest.
BACKUP_SHA256='<reviewed lowercase backup sha256>'

uv run python scripts/align_hosted_namespace_controllers_db.py apply \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --expected-count 223 --expected-present-count 201 \
  --expected-parent-controller-did "$PARENT_DID" \
  --backup "$BACKUP" --backup-sha256 "$BACKUP_SHA256"

uv run python scripts/align_hosted_namespace_controllers_db.py verify \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --expected-count 223 --expected-present-count 201 \
  --expected-parent-controller-did "$PARENT_DID" \
  --backup "$BACKUP" --backup-sha256 "$BACKUP_SHA256"
```

The first command is the default read-only plan. Preserve its output and review
the exact sorted 201-present/22-absent partition. `backup` then writes a
canonical, mode-`0600`, non-overwriting document containing the full 201-row
before-image and the exact 22 absent domains. Preserve and review that file and
its reported SHA-256 before `apply`. `apply` requires that exact digest, uses a
`SERIALIZABLE` transaction and row locks, requires the complete live universe
and every non-controller field to match the backup, and verifies every
postcondition before commit. It is safe to retry. `verify` is also bound to the
same backup and proves the partition and non-controller fields remain exact.

Do not edit the database or either JSON file between these steps. Stop on any
error; the mutation transaction rolls back.

After the operation is applied, independently verified, and its evidence and
backup are preserved, remove this one-time script, its tests, and this runbook
from the repository in a normal reviewed cleanup change.

Restore is break-glass only. It refuses unless every target currently has the
new parent controller and every other column still equals the backup:

```bash
uv run python scripts/align_hosted_namespace_controllers_db.py restore \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --expected-count 223 --expected-present-count 201 \
  --expected-parent-controller-did "$PARENT_DID" \
  --backup "$BACKUP" --backup-sha256 "$BACKUP_SHA256"
```
