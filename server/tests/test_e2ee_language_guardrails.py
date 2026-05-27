from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]


FILES_TO_SCAN = [
    # Extend this list when adding new customer-visible string sources.
    *REPO_ROOT.glob("docs/**/*.md"),
    *REPO_ROOT.glob("skills/**/*.md"),
    *REPO_ROOT.glob("packages/codex-plugin/skills/**/*.md"),
    REPO_ROOT / "channel" / "README.md",
    REPO_ROOT / "docs" / "channel.md",
    REPO_ROOT / "pi-extension" / "README.md",
    REPO_ROOT / "pi-extension" / "src" / "index.ts",
]

FORBIDDEN_PATTERNS = [
    re.compile(r"\bhosted\s+E2E\b", re.IGNORECASE),
    re.compile(r"\bdashboard\s+E2E\b", re.IGNORECASE),
    re.compile(r"\bcustodial\b[^\n.]{0,80}\bend-to-end encrypted\b", re.IGNORECASE),
    re.compile(r"\bend-to-end encrypted\b[^\n.]{0,80}\bcustodial\b", re.IGNORECASE),
    re.compile(r"\bautomatic\s+plaintext\s+fallback\b", re.IGNORECASE),
]


def test_customer_language_does_not_call_hosted_custodial_e2ee() -> None:
    offenders: list[str] = []
    for path in sorted({p for p in FILES_TO_SCAN if p.exists() and p.is_file()}):
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            if match:
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}: {match.group(0)!r}")

    assert not offenders, "Forbidden E2E hosted/custodial wording found:\n" + "\n".join(offenders)
