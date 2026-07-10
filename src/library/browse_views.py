from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

import bleach
import yaml
from fastapi import HTTPException
from markdown_it import MarkdownIt
from pgdbm import AsyncDatabaseManager

from library.repository import get_blueprint, get_blueprint_profile, list_blueprints

_MARKDOWN = MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])
_ALLOWED_TAGS = frozenset(
    {
        "a",
        "blockquote",
        "br",
        "code",
        "dd",
        "div",
        "dl",
        "dt",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "li",
        "ol",
        "p",
        "pre",
        "span",
        "strong",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
        "ul",
    }
)
_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "code": ["class"],
    "th": ["align"],
    "td": ["align"],
}
_ALLOWED_PROTOCOLS = frozenset({"http", "https", "mailto"})


def render_markdown(markdown: str) -> str:
    """Render user/catalog markdown to sanitized inner HTML.

    Catalog markdown is public and server-readable, but still untrusted HTML. We let
    markdown-it-py produce normal CommonMark (including fenced code language
    classes), then bleach strips raw HTML tags/attributes outside the allowlist and
    removes unsafe URL protocols such as ``data:``.
    """

    rendered = _MARKDOWN.render(markdown or "")
    return bleach.clean(
        rendered,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )


def parse_skill_markdown(markdown: str) -> dict[str, Any]:
    """Split optional YAML frontmatter from SKILL.md and render the body safely."""

    frontmatter: dict[str, Any] = {}
    body = markdown or ""
    lines = body.splitlines()
    if lines and lines[0].strip() == "---":
        for index in range(1, len(lines)):
            if lines[index].strip() == "---":
                raw = "\n".join(lines[1:index])
                parsed = yaml.safe_load(raw) or {}
                if isinstance(parsed, dict):
                    frontmatter = {str(key): value for key, value in parsed.items()}
                body = "\n".join(lines[index + 1 :]).lstrip("\n")
                break
    return {"frontmatter": frontmatter, "body_html": render_markdown(body)}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _files_by_path(files: Any) -> dict[str, dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for entry in _as_list(files):
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            by_path[entry["path"]] = entry
    return by_path


def _file_text(files: dict[str, dict[str, Any]], path: str) -> str | None:
    entry = files.get(path)
    if not isinstance(entry, dict):
        return None
    text = entry.get("content_utf8")
    return text if isinstance(text, str) else None


def _profile_yaml(files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    text = _file_text(files, "profile.yaml")
    if text is None:
        return {}
    parsed = yaml.safe_load(text) or {}
    return parsed if isinstance(parsed, dict) else {}


def _safe_path_name(path: str) -> str:
    return PurePosixPath(path).name or path


def _skill_name_from_path(path: str) -> str | None:
    parts = PurePosixPath(path).parts
    if len(parts) == 3 and parts[0] == "skills" and parts[2] == "SKILL.md" and parts[1]:
        return parts[1]
    return None


def _quoted(value: str) -> str:
    return quote(value, safe="")


def _profile_href(blueprint_ref: str, profile_ref: str) -> str:
    return f"/blueprints/{_quoted(blueprint_ref)}/profiles/{_quoted(profile_ref)}"


def _skill_href(blueprint_ref: str, profile_ref: str, skill_name: str) -> str:
    return f"{_profile_href(blueprint_ref, profile_ref)}/skills/{_quoted(skill_name)}"


def _profile_api_href(blueprint_ref: str, profile_ref: str) -> str:
    return f"/v1/blueprints/{_quoted(blueprint_ref)}/profiles/{_quoted(profile_ref)}"


def _first_present(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _profile_recommendation_map(recommendations: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in _as_list(recommendations):
        if not isinstance(item, dict):
            continue
        profile_ref = item.get("id") or item.get("profile_ref")
        if profile_ref:
            result[str(profile_ref)] = item
    return result


def build_blueprint_roster(blueprint: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = [item for item in _as_list(blueprint.get("profiles")) if isinstance(item, dict)]
    recommendations = _profile_recommendation_map(blueprint.get("recommendations"))
    seen: set[str] = set()
    roster: list[dict[str, Any]] = []

    for profile in profiles:
        profile_ref = str(profile.get("profile_ref") or profile.get("id") or "")
        if not profile_ref:
            continue
        seen.add(profile_ref)
        recommendation = recommendations.get(profile_ref, {})
        roster.append(
            {
                "profile_ref": profile_ref,
                "name": profile.get("name") or profile_ref,
                "mission": profile.get("mission"),
                "href": _profile_href(str(blueprint["blueprint_ref"]), profile_ref),
                "default_count": recommendation.get("default_count"),
                "count_min": _first_present(recommendation, "min", "count_min"),
                "count_max": _first_present(recommendation, "max", "count_max"),
                "runtime_hints": [str(item) for item in _as_list(recommendation.get("runtime_hints"))],
            }
        )

    for profile_ref, recommendation in recommendations.items():
        if profile_ref in seen:
            continue
        roster.append(
            {
                "profile_ref": profile_ref,
                "name": profile_ref,
                "mission": None,
                "href": _profile_href(str(blueprint["blueprint_ref"]), profile_ref),
                "default_count": recommendation.get("default_count"),
                "count_min": _first_present(recommendation, "min", "count_min"),
                "count_max": _first_present(recommendation, "max", "count_max"),
                "runtime_hints": [str(item) for item in _as_list(recommendation.get("runtime_hints"))],
            }
        )
    return roster


def build_profile_view(profile: dict[str, Any]) -> dict[str, Any]:
    files = _files_by_path(profile.get("files"))
    profile_yaml = _profile_yaml(files)
    blueprint_ref = str(profile["blueprint_ref"])
    profile_ref = str(profile["profile_ref"])

    instructions_path = profile_yaml.get("instructions")
    if not isinstance(instructions_path, str) or instructions_path not in files:
        instructions_path = "instructions.md" if "instructions.md" in files else "AGENTS.md"
    instructions = _file_text(files, instructions_path) or ""

    skill_paths: list[str] = []
    for item in _as_list(profile_yaml.get("skills")):
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            skill_paths.append(item["path"])
    for path in files:
        if _skill_name_from_path(path) and path not in skill_paths:
            skill_paths.append(path)

    skills: list[dict[str, str]] = []
    for path in skill_paths:
        skill_name = _skill_name_from_path(path)
        text = _file_text(files, path)
        if skill_name is None or text is None:
            continue
        parsed = parse_skill_markdown(text)
        frontmatter = parsed["frontmatter"]
        display_name = str(frontmatter.get("name") or skill_name)
        skills.append(
            {
                "name": display_name,
                "description": str(frontmatter.get("description") or ""),
                "href": _skill_href(blueprint_ref, profile_ref, skill_name),
            }
        )

    artifact_paths: list[str] = []
    for item in _as_list(profile_yaml.get("artifacts")):
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            artifact_paths.append(item["path"])
    excluded = {"profile.yaml", instructions_path, *skill_paths}
    skill_dirs = {"/".join(path.split("/")[:2]) for path in skill_paths}
    for path in files:
        if any(path.startswith(f"{skill_dir}/") for skill_dir in skill_dirs):
            continue
        if path not in excluded and path not in artifact_paths:
            artifact_paths.append(path)

    artifact_href = _profile_api_href(blueprint_ref, profile_ref)
    artifacts = [
        {"name": _safe_path_name(path), "href": artifact_href}
        for path in artifact_paths
        if path in files
    ]

    view = dict(profile)
    view.update(
        {
            "instructions_html": render_markdown(instructions),
            "skills": skills,
            "artifacts": artifacts,
        }
    )
    return view


def build_skill_view(profile: dict[str, Any], skill_name: str) -> dict[str, Any]:
    files = _files_by_path(profile.get("files"))
    skill_path = f"skills/{skill_name}/SKILL.md"
    text = _file_text(files, skill_path)
    if text is None:
        raise HTTPException(status_code=404, detail="Skill not found in profile")
    parsed = parse_skill_markdown(text)
    return {
        "blueprint_ref": profile["blueprint_ref"],
        "profile_ref": profile["profile_ref"],
        "skill_name": skill_name,
        "frontmatter": parsed["frontmatter"],
        "body_html": parsed["body_html"],
    }


async def catalog_view(db: AsyncDatabaseManager) -> list[dict[str, Any]]:
    blueprints = await list_blueprints(db, tags=None)
    result: list[dict[str, Any]] = []
    for blueprint in blueprints:
        view = dict(blueprint)
        try:
            detail = await get_blueprint(db, blueprint_ref=str(blueprint["blueprint_ref"]))
        except HTTPException:
            detail = {}
        profiles = [item for item in _as_list(detail.get("profiles")) if isinstance(item, dict)]
        view["profile_count"] = len(profiles)
        view["profiles"] = profiles
        result.append(view)
    return result


async def blueprint_view(db: AsyncDatabaseManager, *, blueprint_ref: str) -> dict[str, Any]:
    blueprint = await get_blueprint(db, blueprint_ref=blueprint_ref)
    view = dict(blueprint)
    view["roster"] = build_blueprint_roster(blueprint)
    view["profile_count"] = len(view["roster"])
    return view


async def profile_view(
    db: AsyncDatabaseManager, *, blueprint_ref: str, profile_ref: str
) -> dict[str, Any]:
    profile = await get_blueprint_profile(db, blueprint_ref=blueprint_ref, profile_ref=profile_ref)
    return build_profile_view(profile)


async def skill_view(
    db: AsyncDatabaseManager, *, blueprint_ref: str, profile_ref: str, skill_name: str
) -> dict[str, Any]:
    profile = await get_blueprint_profile(db, blueprint_ref=blueprint_ref, profile_ref=profile_ref)
    return build_skill_view(profile, skill_name)
