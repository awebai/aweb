#!/usr/bin/env python3
"""Keep the retired registry lock and detached effect APIs out of live source."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REMOVED_PATHS = (
    "awid/src/awid/protected_effect.py",
    "awid/src/awid/protected_membership.py",
    "awid/src/awid/protected_receipts.py",
    "awid/src/awid_service/protected_teams.py",
    "awid/src/awid_service/routes/protected_effect_receipts.py",
    "server/src/aweb/membership.py",
    "server/src/aweb/protected_signing/effects.py",
    "naapp-lib/src/aweb_naapp/runtime/protected_effect_receipts.py",
    "naapp-lib/src/aweb_naapp/runtime/protected_signer/retention.py",
    "cli/go/awid/protected_effect.go",
    "docs/protected-team-boundary.md",
    "docs/protected-operation-retention.md",
    "docs/vectors/protected-effect-v1.json",
    "docs/vectors/protected-effect-receipt-v1.json",
    "docs/vectors/protected-membership-v1.json",
)
REMOVED_NAMES = (
    "observe_team_protection", "TeamProtectionObservation",
    "verify_registered_membership", "resolve_registered_membership",
    "verify_retained_membership", "effect_transaction", "advance_incarnation",
    "provision_team_protection", "team_authority_for", "protected_delivery",
    "record_applied", "X-AWEB-Protected-Effect", "retained_effect",
    "RetainedEffect", "RetainedEffectCustody", "EffectConfirmation",
    "_retain_authorized_effect", "_reconcile_retained", "_load_retained",
    "AWEB_PROTECTED_SERVICE_KEY_FILE", "AWEB_PROTECTED_EFFECT_RECEIPT_ORIGINS",
    "protected_effect_receipts", "team_protection", "ProtectedArtifactDigest",
)
PATTERN = re.compile(r"\b(?:" + "|".join(map(re.escape, REMOVED_NAMES)) + r")\b")
# These are bounded historical inputs / forward deletion, not live APIs.
EXEMPT_FILES = frozenset((
    "scripts/check_retired_protection.py", "scripts/test_check_retired_protection.py",
    "awid/tests/test_retired_lock_upgrade.py",
    "awid/tests/fixtures/retired_lock_migrations/awid/012_team_protection.sql",
    "awid/tests/fixtures/retired_lock_migrations/awid/013_team_protection_history.sql",
    "awid/tests/fixtures/retired_lock_migrations/awid/014_team_protection_approval.sql",
    "awid/tests/fixtures/retired_lock_migrations/awid/015_protected_effect_receipts.sql",
    "awid/tests/fixtures/retired_lock_migrations/hooks/002_protected_effect_receipts.sql",
    "awid/tests/fixtures/retired_lock_migrations/signer/004_retained_effect.sql",
    "awid/src/awid_service/migrations/016_drop_retired_team_protection.sql",
    "naapp-lib/src/aweb_naapp/hooks/migrations/003_drop_retired_effect_receipts.sql",
    "naapp-lib/src/aweb_naapp/runtime/protected_signer/migrations/011_drop_retired_effect.sql",
))
TEXT_SUFFIXES = {".py", ".go", ".md", ".json", ".sql", ".yaml", ".yml", ".toml", ".js", ".mjs", ".cjs", ".sh"}


def violations(root: Path, paths: list[str]) -> list[str]:
    errors = [f"removed path exists: {name}" for name in REMOVED_PATHS if (root / name).exists()]
    for name in paths:
        if name in EXEMPT_FILES or name.startswith("knowledge/"):
            continue
        path = root / name
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = PATTERN.search(line)
            if match:
                errors.append(f"{name}:{number}: retired name {match.group()}")
    return errors


def main() -> int:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    errors = violations(ROOT, [p for p in paths if p])
    if errors:
        print("Retired protection check failed:\n" + "\n".join(errors))
        return 1
    print("Retired protection check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
