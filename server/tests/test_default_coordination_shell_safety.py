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

    # The hazard is an interpolating CONTEXT, not one command's argument. The earlier
    # wording named the surface - a double-quoted argument to `aw` - and someone
    # following it used --body-file as instructed and was still bitten, in the heredoc
    # that wrote the file. Each assertion below fails against that wording.
    assert "The hazard is a mechanism, not a surface" in instructions
    assert "interpolates" in instructions
    # Naming the safe forms is what makes the rule actionable rather than a warning.
    assert "<<'EOF'" in instructions
    assert "printf '%s'" in instructions
    # And the check that catches it after the fact, with the asymmetry that bounds it.
    assert "grep -c" in instructions
    assert "cannot distinguish" in instructions
    assert "Markdown, reports, or command examples" in instructions
    assert instructions.count("--body-file") >= 7
    assert '--body "' not in instructions
    assert '<alias> "question"' not in instructions
