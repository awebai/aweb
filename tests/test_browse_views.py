from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import library.api as library_api
from library import browse_views
from library.config import Settings

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
"""
    )

    assert "<h1>Heading</h1>" in html
    assert "<li>one</li>" in html
    assert "<pre><code" in html
    assert "language-python" in html
    assert "<script" not in html
    assert "onload" not in html
    assert "data:text/html" not in html


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
                {"id": "coordinator", "default_count": 1, "min": 1, "max": 1, "runtime_hints": ["pi"]},
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


class _FakeDB:
    pass


def _app_with_db_override() -> object:
    app = library_api.create_app(Settings(public_origin="https://library.aweb.ai"))

    def walk(dependant) -> None:
        for sub in dependant.dependencies:
            walk(sub)
        call = dependant.call
        if getattr(call, "__name__", "") == "db":
            app.dependency_overrides[call] = lambda: _FakeDB()

    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is not None:
            walk(dependant)
    return app


def test_browse_routes_call_view_builders_and_renderers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    async def catalog_view(db):
        calls.append(("catalog_view", db))
        return [{"blueprint_ref": "aweb.team", "profile_count": 1}]

    async def blueprint_view(db, *, blueprint_ref):
        calls.append(("blueprint_view", blueprint_ref))
        return {"blueprint_ref": blueprint_ref}

    async def profile_view(db, *, blueprint_ref, profile_ref):
        calls.append(("profile_view", (blueprint_ref, profile_ref)))
        return {"blueprint_ref": blueprint_ref, "profile_ref": profile_ref}

    async def skill_view(db, *, blueprint_ref, profile_ref, skill_name):
        calls.append(("skill_view", (blueprint_ref, profile_ref, skill_name)))
        return {"blueprint_ref": blueprint_ref, "profile_ref": profile_ref, "skill_name": skill_name}

    monkeypatch.setattr(library_api.browse_views, "catalog_view", catalog_view)
    monkeypatch.setattr(library_api.browse_views, "blueprint_view", blueprint_view)
    monkeypatch.setattr(library_api.browse_views, "profile_view", profile_view)
    monkeypatch.setattr(library_api.browse_views, "skill_view", skill_view)
    monkeypatch.setattr(
        library_api.browse,
        "render_catalog_page",
        lambda *, public_origin, blueprints: f"catalog:{public_origin}:{blueprints[0]['blueprint_ref']}",
    )
    monkeypatch.setattr(
        library_api.browse,
        "render_blueprint_page",
        lambda *, public_origin, blueprint: f"blueprint:{blueprint['blueprint_ref']}",
    )
    monkeypatch.setattr(
        library_api.browse,
        "render_profile_page",
        lambda *, public_origin, profile: f"profile:{profile['profile_ref']}",
    )
    monkeypatch.setattr(
        library_api.browse,
        "render_skill_page",
        lambda *, public_origin, skill: f"skill:{skill['skill_name']}",
    )

    client = TestClient(_app_with_db_override())
    responses = [
        client.get("/blueprints"),
        client.get("/blueprints/aweb.team"),
        client.get("/blueprints/aweb.team/profiles/developer"),
        client.get("/blueprints/aweb.team/profiles/developer/skills/implement"),
    ]

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert all(response.headers["content-type"].startswith("text/html") for response in responses)
    assert responses[0].text == "catalog:https://library.aweb.ai:aweb.team"
    assert responses[1].text == "blueprint:aweb.team"
    assert responses[2].text == "profile:developer"
    assert responses[3].text == "skill:implement"
    assert calls[1:] == [
        ("blueprint_view", "aweb.team"),
        ("profile_view", ("aweb.team", "developer")),
        ("skill_view", ("aweb.team", "developer", "implement")),
    ]


def test_browse_unknown_ref_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    async def missing_blueprint(db, *, blueprint_ref):
        raise HTTPException(status_code=404, detail="Blueprint not found")

    monkeypatch.setattr(library_api.browse_views, "blueprint_view", missing_blueprint)
    response = TestClient(_app_with_db_override()).get("/blueprints/missing")
    assert response.status_code == 404
