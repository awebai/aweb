"""Locating aweb and aweb-naapp from inside folio, in either repository layout.

A few of folio's tests read files that belong to aweb: the team-auth envelope conformance
vector, the crypto signature vector, and aweb's server source, which the envelope tests
import so both implementations can be checked against the same bytes.

Where aweb sits relative to folio is changing. Today folio is a SIBLING checkout of aweb;
after the naapp move folio lives at aweb/naapp/folio and aweb is an ANCESTOR. Every helper
here searches both, so one test file works either side of the move and nothing has to be
edited in the same commit that performs it.

Nothing here falls back to skipping, and that is deliberate. These are cross-repo
conformance checks. A conformance check that fails gets fixed; one that silently stops
running does not, because a green suite is indistinguishable from a passing one. The
previous form of this logic was `if path.exists(): sys.path.insert(...)`, which is exactly
that silent form - after the move it stopped finding aweb and simply did less.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

_FOLIO_ROOT = Path(__file__).resolve().parents[1]


def aweb_candidate_roots() -> list[Path]:
    """Every directory aweb's root could be, nearest first.

    The sibling checkout is tried first because that is the layout while the two repos
    exist separately. The ancestors cover the post-move layout, where folio is inside
    aweb.
    """
    return [_FOLIO_ROOT.parent / "aweb", *_FOLIO_ROOT.parents]


def aweb_path(*parts: str) -> Path:
    """Path to a file inside the aweb repository.

    Raises FileNotFoundError naming everywhere it looked, rather than returning a path
    that does not exist: a caller handed a missing path either crashes further away from
    the cause or, worse, treats it as a reason to do nothing.
    """
    tried: list[Path] = []
    for root in aweb_candidate_roots():
        candidate = root.joinpath(*parts)
        tried.append(candidate)
        if candidate.exists():
            return candidate
    joined = "/".join(parts)
    raise FileNotFoundError(
        f"could not locate aweb/{joined} from {_FOLIO_ROOT}. These are cross-repo "
        "conformance inputs and must not be skipped. Looked in: "
        + ", ".join(str(path) for path in tried)
    )


def aweb_naapp_local_source_candidates() -> list[Path]:
    """Every place a LOCAL aweb-naapp source tree could sit.

    folio depends on aweb-naapp as a pinned package, and test_surfaces asserts the import
    resolves from that package rather than from a source tree lying around next to it.
    Which source tree that could be depends on the layout: the sibling aweb-naapp checkout
    today, and aweb/naapp-lib once the move puts it inside aweb.

    Both are listed because a guard that names only the location which has stopped
    existing still passes - it just can no longer fail. That is what happened to this
    guard when the move was rehearsed: its subject became a path that can never exist, at
    the same moment aweb-naapp's source arrived in the tree under a different name.
    """
    candidates = [_FOLIO_ROOT.parent / "aweb-naapp" / "src"]
    candidates.extend(root / "naapp-lib" / "src" for root in aweb_candidate_roots())
    return candidates


def existing_local_sources(candidates: Iterable[Path]) -> list[Path]:
    """The candidates that actually exist - the ones the guard can be tested against.

    Separated out so a test can assert it found a subject at all. A guard checking only
    locations that do not exist reports success without having looked at anything.
    """
    return [candidate for candidate in candidates if candidate.exists()]


def shadowing_local_source(package_file: Path | str, candidates: Iterable[Path]) -> Path | None:
    """The local source tree an imported package came from, or None if it did not.

    Kept as a plain function of its inputs so it can be exercised in both directions. The
    import it is normally asked about resolves from the pinned package, so the failing case
    cannot be produced by importing anything - it has to be constructed, and a decision
    that cannot be constructed is one nobody has watched fail.
    """
    resolved = Path(package_file).resolve()
    for candidate in candidates:
        if candidate.exists() and candidate in resolved.parents:
            return candidate
    return None
