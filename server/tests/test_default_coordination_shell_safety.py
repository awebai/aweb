from aweb.coordination.defaults import get_default_bundle, get_default_team_instructions

# Inline message bodies a shell would interpolate. The shipped defaults teach
# file bodies instead, so neither form may appear in any of them.
UNSAFE_BODY_FORMS = ('--body "', '<alias> "question"')


def shipped_documents() -> dict[str, str]:
    roles = get_default_bundle(force_reload=True)["roles"]
    documents = {f"role {name}": role["playbook_md"] for name, role in roles.items()}
    documents["team instructions"] = get_default_team_instructions(force_reload=True)[
        "body_md"
    ]
    return documents


def test_no_shipped_default_teaches_an_inline_message_body() -> None:
    for name, text in shipped_documents().items():
        for form in UNSAFE_BODY_FORMS:
            assert form not in text, f"{name} contains {form!r}"


def test_default_team_instructions_name_the_non_interpolating_forms() -> None:
    instructions = get_default_team_instructions(force_reload=True)["body_md"]
    assert "--body-file" in instructions
    assert "<<'EOF'" in instructions
    assert "printf '%s'" in instructions
