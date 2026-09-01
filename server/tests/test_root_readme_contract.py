from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")


def test_root_readme_leads_from_value_to_evaluation() -> None:
    expected_sections = [
        "## Why aweb",
        "## See a durable round trip",
        "## Try aweb",
        "## Runtime integrations",
        "## Hosting and authority",
        "## What is in this repository",
        "## Documentation",
        "## Current limitations",
    ]

    positions = [README.index(section) for section in expected_sections]
    assert positions == sorted(positions)

    opening = " ".join(README[: README.index("## Why aweb")].split())
    assert "durable mail and chat" in opening
    assert "wake-up events" in opening
    assert "sessions, runtimes, and machines" in opening


def test_root_readme_contains_a_complete_evaluation_path() -> None:
    assert "[aweb.ai hosted service](https://aweb.ai/)" in README
    assert "generous free tier" in README

    for command in [
        "npm install -g @awebai/aw",
        "aw init --username <username> --name alice",
        "aw team invite",
        "aw team join <invite-token> --name bob",
        "aw events stream --json",
        'aw mail send --to bob --subject "review requested"',
        '--body "Please review this branch and reply in the same conversation."',
        "aw mail show --message-id <message-id>",
        "cat > reply.md <<'EOF'",
        "aw mail reply <message-id>",
    ]:
        assert command in README

    for link in [
        "docs/cli-tutorial.md",
        "docs/self-hosting-guide.md",
        "docs/receiving-events.md",
        "docs/product-authority-sot.md",
        "docs/current-limitations.md",
        "docs/README.md",
    ]:
        assert f"]({link})" in README
        assert (REPO_ROOT / link).is_file()


def test_root_readme_does_not_lead_with_internal_ownership() -> None:
    assert "## What owns what" not in README
