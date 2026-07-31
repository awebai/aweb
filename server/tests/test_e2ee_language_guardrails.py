import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


FILES_TO_SCAN = [
    # Extend this list when adding new customer-visible string sources.
    REPO_ROOT / "README.md",
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

PUBLIC_E2E_DOCS = [
    REPO_ROOT / "docs" / "e2e-messaging-contract.md",
    REPO_ROOT / "docs" / "e2e-operational-metadata.md",
    REPO_ROOT / "docs" / "e2e-legacy-plaintext-policy.md",
    REPO_ROOT / "docs" / "e2e-release-rollout-runbook.md",
    REPO_ROOT / "docs" / "e2e-library-stack.md",
]

PRIVATE_CUSTODIAL_TRANSITION_SOURCE = (
    REPO_ROOT / "docs" / "custodial-managed-encryption.md"
)
PRIVATE_CUSTODIAL_TRANSITION_INVENTORY_LABEL = "Hosted custody implementation contract"

FORBIDDEN_PUBLIC_IMPLEMENTATION_PATTERNS = [
    re.compile(r"\bAC\b"),
    re.compile(r"\baweb-[a-z]{4}(?:\.\d+)*\b"),
    re.compile(r"default-[a-z]+"),
    re.compile(r"aweb_cloud"),
    re.compile(r"\bRender\b"),
    re.compile(r"\b(?:Athena|Mia|Hestia)\b"),
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

    assert not offenders, "Forbidden E2E hosted/custodial wording found:\n" + "\n".join(
        offenders
    )


def _public_e2ee_reference_offenders(
    overrides: dict[Path, str] | None = None,
) -> list[str]:
    offenders: list[str] = []
    overrides = overrides or {}
    for path in PUBLIC_E2E_DOCS:
        if not path.is_file():
            continue
        text = overrides.get(path, path.read_text(encoding="utf-8"))
        for pattern in FORBIDDEN_PUBLIC_IMPLEMENTATION_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{line}: {match.group(0)!r}"
                )
    return offenders


def test_public_e2ee_family_has_no_private_implementation_or_task_references() -> None:
    offenders = _public_e2ee_reference_offenders()

    assert not offenders, "Private implementation/task references found:\n" + "\n".join(
        offenders
    )


def test_public_e2ee_task_reference_guard_rejects_current_task_id() -> None:
    path = PUBLIC_E2E_DOCS[0]
    text = path.read_text(encoding="utf-8") + "\nTracked internally as aweb-aazc.\n"

    offenders = _public_e2ee_reference_offenders({path: text})
    line = text.count("\n", 0, text.index("aweb-aazc")) + 1

    assert offenders == [f"{path.relative_to(REPO_ROOT)}:{line}: 'aweb-aazc'"]


def _tracked_markdown_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(
        REPO_ROOT / relative_path
        for relative_path in result.stdout.split("\0")
        if relative_path
    )


def _private_custodial_transition_reference_offenders(
    overrides: dict[Path, str] | None = None,
) -> list[str]:
    offenders: list[str] = []
    overrides = overrides or {}
    for path in _tracked_markdown_files():
        if not path.is_file():
            continue
        text = overrides.get(path, path.read_text(encoding="utf-8"))
        for forbidden in [
            PRIVATE_CUSTODIAL_TRANSITION_SOURCE.name,
            PRIVATE_CUSTODIAL_TRANSITION_INVENTORY_LABEL,
        ]:
            if forbidden in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {forbidden!r}")
    return offenders


def test_private_custodial_transition_source_is_absent_and_not_indexed() -> None:
    assert not PRIVATE_CUSTODIAL_TRANSITION_SOURCE.exists()
    assert not _private_custodial_transition_reference_offenders()


def test_private_custodial_transition_guard_scans_root_readme() -> None:
    path = REPO_ROOT / "README.md"
    text = path.read_text(encoding="utf-8") + (
        "\n[Removed managed custody source](docs/custodial-managed-encryption.md)\n"
    )

    offenders = _private_custodial_transition_reference_offenders({path: text})

    assert offenders == ["README.md: 'custodial-managed-encryption.md'"]


def test_private_custodial_transition_guard_scans_all_tracked_markdown() -> None:
    path = REPO_ROOT / "CONTRIBUTING.md"
    text = path.read_text(encoding="utf-8") + (
        "\nRemoved transition inventory: Hosted custody implementation contract\n"
    )

    offenders = _private_custodial_transition_reference_offenders({path: text})

    assert offenders == ["CONTRIBUTING.md: 'Hosted custody implementation contract'"]
