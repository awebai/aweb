"""Modes for public, disposable fixtures shared across container users."""

from pathlib import Path
import stat


def make_public_tree_readable(*, root: Path) -> None:
    """Normalize an owned public-code tree without following external symlinks."""
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode):
            path.chmod(0o755)
        elif stat.S_ISREG(mode):
            path.chmod(0o755 if mode & 0o111 else 0o644)


def prepare_fixture_permissions(*, root: Path) -> None:
    """Expose only test code and throwaway TLS material to container users."""
    # The folio/grant fixture volume is read by services with distinct UIDs.
    # Identity homes and evidence are outside these three public directories.
    root.chmod(0o755)
    for name in ("e2e", "test-support", "tls"):
        make_public_tree_readable(root=root / name)
