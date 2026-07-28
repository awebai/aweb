from pathlib import Path


DEFAULTS = Path(__file__).parents[1] / "src" / "aweb" / "defaults"


def read_default(relative_path: str) -> str:
    return (DEFAULTS / relative_path).read_text()


def test_default_roles_use_file_inputs_for_multiline_reports() -> None:
    developer = read_default("roles/developer.md")
    coordinator = read_default("roles/coordinator.md")

    assert '--body "Summary: ...' not in developer
    assert developer.count("--body-file") >= 3
    assert '--body "Goal: ...' not in coordinator
    assert '--body "Please review <ref>.' not in coordinator
    assert coordinator.count("--body-file") >= 3


def test_default_team_instructions_teach_shell_safe_long_bodies() -> None:
    instructions = read_default("team_instructions.md")

    assert "before `aw` starts" in instructions
    assert "Markdown, reports, or command examples" in instructions
    assert instructions.count("--body-file") >= 7
    assert '--body "' not in instructions
    assert '<alias> "question"' not in instructions
