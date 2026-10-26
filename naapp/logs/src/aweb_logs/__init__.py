"""logs: an AWID team's tamper-evident audit log of hook events, read only by its owner's designated readers."""

from pathlib import Path

# logs' manifest template: kids and purposes, never keys. A deployment fills
# each kid's did:key from its configured key file before serving it.
MANIFEST_PATH = Path(__file__).resolve().parent / "aweb-app.json"

# logs' own migrations, applied after the shared naapp ones under this module name.
MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_logs"
