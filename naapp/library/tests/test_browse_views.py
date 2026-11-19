from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from library import browse_views

_PROFILE = {
    "blueprint_ref": "aweb.team",
    "blueprint_version": "0.1.0",
    "profile_ref": "developer",
    "version": "0.1.0",
    "digest": "sha256:profile",
    "name": "Developer",
    "mission": "Implement scoped changes.",
    "accepted_work": ["implementation"],
    "runtime_assumptions": ["local shell"],
    "runtime_hints": ["claude-code"],
    "memory_policy": {"mode": "reviewed-learning"},
    "expected_apps": ["tasks"],
    "event_subscriptions": [],
    "approval_required": ["github.merge_pr"],
    "files": [
        {
            "path": "profile.yaml",
            "sha256": "sha256:profile-yaml",
            "content_utf8": """id: developer
name: Developer
version: 0.1.0
mission: Implement scoped changes.
instructions: instructions.md
artifacts:
  - path: artifacts/handoff-template.md
    kind: handoff_template
skills:
  - path: skills/implement/SKILL.md
    kind: skill
""",
        },
        {
            "path": "instructions.md",
            "sha256": "sha256:instructions",
            "content_utf8": """# Instructions

- keep changes small
- run tests

```python
print("ok")
```

<script>alert("x")</script>
<svg onload="alert('x')"></svg>
<a href="data:text/html,evil" onload="alert('x')">bad link</a>
""",
        },
        {
            "path": "skills/implement/SKILL.md",
            "sha256": "sha256:skill",
            "content_utf8": """---
name: implement
description: Ship scoped code changes.
allowed-tools: Bash, Read
---
# Implement

Use lists:

1. inspect
2. patch

```bash
pytest
```

<img src="data:image/svg+xml,evil" onload="alert('x')">
""",
        },
        {
            "path": "artifacts/handoff-template.md",
            "sha256": "sha256:artifact",
            "content_utf8": "# Handoff\n",
        },
    ],
}


def test_markdown_renderer_preserves_commonmark_and_strips_unsafe_html() -> None:
    html = browse_views.render_markdown(
        """# Heading

- one
- two

```python
print("ok")
```

<script>alert("x")</script>
<a href="data:text/html,evil" onload="alert('x')">bad</a>
[bad](javascript:alert(1))
<a href=javascript:alert(1)>raw bad</a>
"""
    )

    assert "<h1>Heading</h1>" in html
    assert "<li>one</li>" in html
    assert "<pre><code" in html
    assert "language-python" in html
    assert "<script" not in html
    assert "onload" not in html
    assert "data:text/html" not in html
    assert 'href="javascript:' not in html
    assert "href=javascript:" not in html
    assert "[bad](javascript:alert(1))" in html  # markdown-it leaves it inert text
    assert "<a>raw bad</a>" in html


def test_profile_view_derives_sanitized_instructions_skills_and_artifacts() -> None:
    view = browse_views.build_profile_view(_PROFILE)

    assert view["instructions_html"].startswith("<h1>Instructions</h1>")
    assert "<li>keep changes small</li>" in view["instructions_html"]
    assert "language-python" in view["instructions_html"]
    assert "<script" not in view["instructions_html"]
    assert "onload" not in view["instructions_html"]
    assert "data:text/html" not in view["instructions_html"]
    assert view["skills"] == [
        {
            "name": "implement",
            "description": "Ship scoped code changes.",
            "href": "/blueprints/aweb.team/profiles/developer/skills/implement",
        }
    ]
    assert view["artifacts"] == [
        {"name": "handoff-template.md", "href": "/v1/blueprints/aweb.team/profiles/developer"}
    ]


def test_skill_view_parses_frontmatter_and_sanitizes_body() -> None:
    view = browse_views.build_skill_view(_PROFILE, "implement")

    assert view["frontmatter"] == {
        "name": "implement",
        "description": "Ship scoped code changes.",
        "allowed-tools": "Bash, Read",
    }
    assert "<h1>Implement</h1>" in view["body_html"]
    assert "<li>inspect</li>" in view["body_html"]
    assert "language-bash" in view["body_html"]
    assert "data:image" not in view["body_html"]
    assert "onload" not in view["body_html"]


def test_skill_view_unknown_skill_is_404() -> None:
    with pytest.raises(HTTPException) as exc:
        browse_views.build_skill_view(_PROFILE, "missing")
    assert exc.value.status_code == 404


def test_blueprint_roster_joins_recommendations_to_profiles() -> None:
    roster = browse_views.build_blueprint_roster(
        {
            "blueprint_ref": "aweb.team",
            "profiles": [
                {"profile_ref": "coordinator", "name": "Coordinator", "mission": "Route work."},
                {"profile_ref": "developer", "name": "Developer", "mission": "Ship code."},
            ],
            "recommendations": [
                {
                    "id": "coordinator",
                    "default_count": 1,
                    "min": 1,
                    "max": 1,
                    "runtime_hints": ["pi"],
                },
                {
                    "id": "developer",
                    "default_count": 2,
                    "min": 1,
                    "max": 4,
                    "runtime_hints": ["claude-code"],
                },
            ],
        }
    )

    assert roster[0]["profile_ref"] == "coordinator"
    assert roster[0]["default_count"] == 1
    assert roster[0]["count_min"] == 1
    assert roster[0]["count_max"] == 1
    assert roster[0]["runtime_hints"] == ["pi"]
    assert roster[0]["href"] == "/blueprints/aweb.team/profiles/coordinator"
    assert roster[1]["mission"] == "Ship code."


def test_the_browse_pages_render_a_published_blueprint(
    published_engineering: TestClient,
) -> None:
    client = published_engineering
    catalog = client.get("/blueprints")
    blueprint = client.get("/blueprints/aweb.engineering")
    profile = client.get("/blueprints/aweb.engineering/profiles/developer")
    skill = client.get("/blueprints/aweb.engineering/profiles/developer/skills/implement")

    for response in (catalog, blueprint, profile, skill):
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/html")
    assert 'href="/blueprints/aweb.engineering"' in catalog.text
    assert 'href="/blueprints/aweb.engineering/profiles/developer"' in blueprint.text
    assert "Implement scoped changes with tests and concise evidence." in profile.text
    assert 'href="/blueprints/aweb.engineering/profiles/developer/skills/implement"' in profile.text
    assert "prefer targeted edits" in skill.text


def test_browse_pages_for_an_unpublished_ref_are_404(
    published_engineering: TestClient,
) -> None:
    client = published_engineering
    for path in (
        "/blueprints/aweb.missing",
        "/blueprints/aweb.engineering/profiles/missing",
        "/blueprints/aweb.engineering/profiles/developer/skills/missing",
    ):
        assert client.get(path).status_code == 404, path
