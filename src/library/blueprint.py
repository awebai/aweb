"""Pure blueprint interpretation.

Parse an import payload (``aweb.blueprint.import-payload.v1``) into blueprint +
profile records with content digests, produce the import-return body, and build
the materialize home layout. No I/O — the repository persists, the API wires.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import yaml

from library.aweb_manifest import canonical_bytes
from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, PROFILE_PAYLOAD_SCHEMA, payload_digest

# Structured-field parts tracked for the per-part update-from-source merge — all the
# behavior/expectation fields, so a profile pulls upstream improvements to any of them
# when un-evolved. Files are tracked per-file ("instructions" lives in instructions.md,
# a file part). name/id/version are never merged.
_BASELINE_FIELDS = (
    "mission",
    "accepted_work",
    "runtime_assumptions",
    "memory_policy",
    "expected_apps",
    "event_subscriptions",
    "approval_required",
)


@dataclass(frozen=True)
class ParsedProfile:
    profile_ref: str
    version: str
    digest: str
    name: str
    mission: str | None
    accepted_work: list[str]
    runtime_assumptions: list[str]
    memory_policy: dict[str, Any] | None
    expected_apps: list[str]
    event_subscriptions: list[dict[str, Any]]
    approval_required: list[str]
    files: list[dict[str, str]]


@dataclass(frozen=True)
class ParsedBlueprint:
    blueprint_ref: str
    version: str
    digest: str
    name: str
    summary: str | None
    description: str | None
    recommendations: list[dict[str, Any]]
    runtime_hints: list[str]
    expected_apps: list[str]
    first_mission_examples: list[str]
    profiles: list[ParsedProfile]
    files: list[dict[str, str]]


def _as_str_list(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _profile_payload_files(blueprint_files: list[dict[str, str]], profile_id: str) -> list[dict[str, str]]:
    """The profile's files re-relativized to PROFILE-relative paths (the form the
    profile digest hashes)."""
    prefix = f"profiles/{profile_id}/"
    out = [
        {"content_utf8": f["content_utf8"], "path": f["path"][len(prefix) :], "sha256": f["sha256"]}
        for f in blueprint_files
        if f["path"].startswith(prefix)
    ]
    out.sort(key=lambda f: f["path"])
    return out


def parse_import_payload(payload: dict[str, Any]) -> ParsedBlueprint:
    """Validate and parse an import-payload.v1 into a blueprint + profiles with digests."""
    if not isinstance(payload, dict) or payload.get("schema") != BLUEPRINT_PAYLOAD_SCHEMA:
        raise ValueError(f"import payload schema must be {BLUEPRINT_PAYLOAD_SCHEMA}")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("import payload must contain files")
    if not all(isinstance(f, dict) and {"content_utf8", "path", "sha256"} <= set(f) for f in files):
        raise ValueError("import payload files must have content_utf8, path, sha256")

    by_path = {f["path"]: f for f in files}
    if "blueprint.yaml" not in by_path:
        raise ValueError("import payload missing blueprint.yaml")
    blueprint_yaml = yaml.safe_load(by_path["blueprint.yaml"]["content_utf8"]) or {}
    blueprint_ref = str(blueprint_yaml["id"])
    blueprint_version = str(blueprint_yaml["version"])
    recommendations = blueprint_yaml.get("profiles") or []

    profiles: list[ParsedProfile] = []
    for recommendation in recommendations:
        profile_id = str(recommendation["id"])
        profile_yaml_path = f"profiles/{profile_id}/profile.yaml"
        if profile_yaml_path not in by_path:
            raise ValueError(f"import payload missing {profile_yaml_path}")
        profile_yaml = yaml.safe_load(by_path[profile_yaml_path]["content_utf8"]) or {}
        profile_files = _profile_payload_files(files, profile_id)
        profiles.append(
            ParsedProfile(
                profile_ref=str(profile_yaml["id"]),
                version=str(profile_yaml["version"]),
                digest=payload_digest(profile_files, PROFILE_PAYLOAD_SCHEMA),
                name=str(profile_yaml.get("name") or profile_id),
                mission=profile_yaml.get("mission"),
                accepted_work=_as_str_list(profile_yaml.get("accepted_work")),
                runtime_assumptions=_as_str_list(profile_yaml.get("runtime_assumptions")),
                memory_policy=profile_yaml.get("memory_policy"),
                expected_apps=_as_str_list(profile_yaml.get("expected_apps")),
                event_subscriptions=list(profile_yaml.get("event_subscriptions") or []),
                approval_required=_as_str_list(profile_yaml.get("approval_required")),
                files=profile_files,
            )
        )

    return ParsedBlueprint(
        blueprint_ref=blueprint_ref,
        version=blueprint_version,
        digest=payload_digest(files, BLUEPRINT_PAYLOAD_SCHEMA),
        name=str(blueprint_yaml.get("name") or blueprint_ref),
        summary=blueprint_yaml.get("summary"),
        description=blueprint_yaml.get("description"),
        recommendations=list(recommendations),
        runtime_hints=_as_str_list(blueprint_yaml.get("runtime_hints")),
        expected_apps=_as_str_list(blueprint_yaml.get("expected_apps")),
        first_mission_examples=_as_str_list(blueprint_yaml.get("first_mission_examples")),
        profiles=profiles,
        files=list(files),
    )


def parse_profile_payload(files: list[dict[str, str]]) -> ParsedProfile:
    """Parse a single profile's payload (profile-payload.v1, PROFILE-relative files)
    into a ParsedProfile with its content digest. Used to create or version a shelf
    profile directly from supplied content."""
    if not isinstance(files, list) or not files:
        raise ValueError("profile payload must contain files")
    if not all(isinstance(f, dict) and {"content_utf8", "path", "sha256"} <= set(f) for f in files):
        raise ValueError("profile payload files must have content_utf8, path, sha256")
    by_path = {f["path"]: f for f in files}
    if "profile.yaml" not in by_path:
        raise ValueError("profile payload missing profile.yaml")
    profile_yaml = yaml.safe_load(by_path["profile.yaml"]["content_utf8"]) or {}
    return ParsedProfile(
        profile_ref=str(profile_yaml["id"]),
        version=str(profile_yaml["version"]),
        digest=payload_digest(files, PROFILE_PAYLOAD_SCHEMA),
        name=str(profile_yaml.get("name") or profile_yaml["id"]),
        mission=profile_yaml.get("mission"),
        accepted_work=_as_str_list(profile_yaml.get("accepted_work")),
        runtime_assumptions=_as_str_list(profile_yaml.get("runtime_assumptions")),
        memory_policy=profile_yaml.get("memory_policy"),
        expected_apps=_as_str_list(profile_yaml.get("expected_apps")),
        event_subscriptions=list(profile_yaml.get("event_subscriptions") or []),
        approval_required=_as_str_list(profile_yaml.get("approval_required")),
        files=sorted(files, key=lambda entry: entry["path"]),
    )


def _field_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def part_baselines(profile: ParsedProfile) -> dict[str, str]:
    """Per-part content digests recorded at copy/sync, for the per-part 3-way merge.
    Parts = each file (its sha256) + each structured field (sha256 of its canonical
    bytes). Keys are namespaced ('file:<path>' / 'field:<name>')."""
    baselines = {f"file:{entry['path']}": entry["sha256"] for entry in profile.files}
    for field in _BASELINE_FIELDS:
        baselines[f"field:{field}"] = _field_digest(getattr(profile, field))
    return baselines


@dataclass(frozen=True)
class MergeResult:
    files: list[dict[str, str]]  # merged PROFILE-relative files incl reconstructed profile.yaml
    updated_parts: list[str]  # parts taken from theirs (upstream improvements pulled)
    preserved_parts: list[str]  # parts kept as ours (locally evolved, upstream change declined)


def _resource_entries(category: str, present_paths: set[str], *docs: dict[str, Any]) -> list[dict[str, str]]:
    """Rebuild profile.yaml's skills/artifacts list from the merged file set, carrying
    each entry's ``kind`` from whichever source profile declared it (ours first)."""
    kinds: dict[str, Any] = {}
    for doc in docs:
        for entry in doc.get(category) or []:
            kinds.setdefault(entry["path"], entry.get("kind"))
    entries: list[dict[str, str]] = []
    for path in sorted(p for p in present_paths if p.startswith(f"{category}/")):
        out: dict[str, str] = {"path": path}
        if kinds.get(path) is not None:
            out["kind"] = kinds[path]
        entries.append(out)
    return entries


def three_way_merge(
    *,
    ours_files: list[dict[str, str]],
    theirs_files: list[dict[str, str]],
    baselines: dict[str, str],
    target_version: str,
) -> MergeResult:
    """Per-part 3-way merge of a shelf profile (ours) against a newer source-blueprint
    version (theirs), given the per-part baselines recorded at last sync. For each
    part (structured field or file), take theirs only where ours is un-evolved
    (ours digest == baseline); otherwise keep ours. profile.yaml is reconstructed
    from the merged fields (name/id always ours, version := target_version); its
    skills/artifacts lists follow the merged file set."""
    ours_by = {f["path"]: f for f in ours_files}
    theirs_by = {f["path"]: f for f in theirs_files}
    ours_doc = yaml.safe_load(ours_by["profile.yaml"]["content_utf8"]) or {}
    theirs_doc = yaml.safe_load(theirs_by["profile.yaml"]["content_utf8"]) or {}

    updated: list[str] = []
    preserved: list[str] = []

    merged_doc = dict(ours_doc)
    for field in _BASELINE_FIELDS:
        base_sha = baselines.get(f"field:{field}")
        ours_sha = _field_digest(ours_doc.get(field))
        theirs_sha = _field_digest(theirs_doc.get(field))
        if theirs_sha == base_sha:
            continue  # no upstream change to this field
        if ours_sha == base_sha:
            merged_doc[field] = theirs_doc.get(field)
            updated.append(f"field:{field}")
        else:
            preserved.append(f"field:{field}")

    merged_files_map: dict[str, dict[str, str]] = {}
    for path in (set(ours_by) | set(theirs_by)) - {"profile.yaml"}:
        base_file_sha = baselines.get(f"file:{path}")
        ours_file_sha = ours_by[path]["sha256"] if path in ours_by else None
        theirs_file_sha = theirs_by[path]["sha256"] if path in theirs_by else None
        if theirs_file_sha == base_file_sha:
            take_theirs = False  # no upstream change
        elif ours_file_sha == base_file_sha:
            updated.append(f"file:{path}")
            take_theirs = True
        else:
            preserved.append(f"file:{path}")
            take_theirs = False
        source = theirs_by if take_theirs else ours_by
        if path in source:
            merged_files_map[path] = source[path]

    merged_doc["version"] = target_version
    merged_doc["skills"] = _resource_entries("skills", set(merged_files_map), ours_doc, theirs_doc)
    merged_doc["artifacts"] = _resource_entries("artifacts", set(merged_files_map), ours_doc, theirs_doc)

    profile_yaml = yaml.safe_dump(merged_doc, sort_keys=False, allow_unicode=True)
    merged_files = [_payload_file("profile.yaml", profile_yaml)]
    merged_files.extend(merged_files_map.values())
    merged_files.sort(key=lambda entry: entry["path"])
    return MergeResult(files=merged_files, updated_parts=sorted(updated), preserved_parts=sorted(preserved))


def _payload_file(path: str, content_utf8: str) -> dict[str, str]:
    return {
        "content_utf8": content_utf8,
        "path": path,
        "sha256": "sha256:" + hashlib.sha256(content_utf8.encode("utf-8")).hexdigest(),
    }


def build_blueprint_payload(
    *,
    blueprint_ref: str,
    blueprint_version: str,
    name: str,
    summary: str | None,
    description: str | None,
    first_mission_examples: list[str],
    readme: str | None,
    prior_files: list[dict[str, str]] | None,
    profile_ref: str,
    profile_files: list[dict[str, str]],
) -> dict[str, Any]:
    """Assemble an import-payload.v1 that publishes a shelf profile into a blueprint.

    The blueprint.yaml is library-generated and the profile set accumulates: the named
    profile is added to (or replaces) any profiles carried from ``prior_files``.
    Re-parsing the result through ``parse_import_payload`` reproduces every profile
    digest (paths round-trip blueprint<->profile relative), so a published profile keeps
    the digest it had on the shelf."""
    prefix = f"profiles/{profile_ref}/"
    carried = [
        f
        for f in (prior_files or [])
        if f["path"] not in ("blueprint.yaml", "README.md") and not f["path"].startswith(prefix)
    ]
    published = [
        {"content_utf8": f["content_utf8"], "path": prefix + f["path"], "sha256": f["sha256"]}
        for f in profile_files
    ]
    content_files = carried + published

    profile_ids = sorted(
        f["path"][len("profiles/") : -len("/profile.yaml")]
        for f in content_files
        if f["path"].startswith("profiles/") and f["path"].endswith("/profile.yaml")
    )
    blueprint_doc: dict[str, Any] = {"id": blueprint_ref, "version": blueprint_version, "name": name}
    if summary is not None:
        blueprint_doc["summary"] = summary
    if description is not None:
        blueprint_doc["description"] = description
    if first_mission_examples:
        blueprint_doc["first_mission_examples"] = first_mission_examples
    blueprint_doc["profiles"] = [{"id": pid} for pid in profile_ids]

    files = [_payload_file("blueprint.yaml", yaml.safe_dump(blueprint_doc, sort_keys=False, allow_unicode=True))]
    if readme is not None:
        files.append(_payload_file("README.md", readme))
    files.extend(content_files)
    files.sort(key=lambda entry: entry["path"])
    return {"files": files, "schema": BLUEPRINT_PAYLOAD_SCHEMA}


def import_return(blueprint: ParsedBlueprint) -> dict[str, Any]:
    """The POST /v1/blueprints/import response body."""
    return {
        "digest": blueprint.digest,
        "blueprint_ref": blueprint.blueprint_ref,
        "version": blueprint.version,
        "profiles": [
            {"profile_ref": profile.profile_ref, "version": profile.version, "digest": profile.digest}
            for profile in blueprint.profiles
        ],
    }


# The proposal target is interpolated (a profile's memory_policy.proposal_target,
# e.g. "library"); the line wrap is fixed regardless of the target's length.
_MEMORY_BOILERPLATE = (
    "Your full profile is kept under .aw/profile/. To change how you work, propose a\n"
    "new profile version from there; {target} reviews and mints it."
)
_SKILLS_BOILERPLATE = "These skills are installed and discoverable by your harness:"


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _skill_name(skill_path: str) -> str:
    # skills/<name>/SKILL.md -> <name>
    return skill_path.split("/")[1]


def _compose_agents_md(doc: dict[str, Any], *, profile_ref: str, instructions: str, provenance: str) -> str:
    """The composed AGENTS.md: a single human-readable rendering of the profile, in
    source order. Empty components omit their whole section (title included)."""
    name = str(doc.get("name") or profile_ref)
    blocks = [f"# {name}\n\n> Profile {profile_ref} v{doc['version']} · {provenance}"]

    mission = doc.get("mission")
    if mission:
        blocks.append(f"## Mission\n\n{mission}")
    accepted_work = [str(item) for item in doc.get("accepted_work") or []]
    if accepted_work:
        blocks.append(f"## Work you take on\n\n{_bullets(accepted_work)}")
    if instructions.strip():
        blocks.append(f"## Instructions\n\n{instructions.rstrip(chr(10))}")
    expected_apps = [str(item) for item in doc.get("expected_apps") or []]
    if expected_apps:
        blocks.append(f"## Apps you use\n\n{_bullets(expected_apps)}")
    approval_required = [str(item) for item in doc.get("approval_required") or []]
    if approval_required:
        blocks.append(f"## Actions requiring human approval\n\n{_bullets(approval_required)}")
    memory_policy = doc.get("memory_policy") or {}
    if memory_policy:
        mode = memory_policy.get("mode", "")
        target = memory_policy.get("proposal_target", "")
        boilerplate = _MEMORY_BOILERPLATE.format(target=target)
        blocks.append(f"## Memory and learning\n\nMode: {mode}\nProposal target: {target}\n\n{boilerplate}")
    skill_names = [_skill_name(str(skill["path"])) for skill in doc.get("skills") or []]
    if skill_names:
        blocks.append(f"## Skills\n\n{_SKILLS_BOILERPLATE}\n\n{_bullets(skill_names)}")

    return "\n\n".join(blocks) + "\n"


def materialize_home(
    files: list[dict[str, str]],
    *,
    profile_ref: str,
    profile_version: str,
    profile_digest: str,
    source_blueprint_ref: str | None,
    source_blueprint_version: str | None,
    source_blueprint_digest: str | None,
) -> list[dict[str, str]]:
    """The composed agent home a runtime materialization writes, as ``file`` and
    ``symlink`` entries:

    - ``AGENTS.md`` — the composed profile rendering; ``CLAUDE.md`` symlinks to it.
    - ``skills/<name>/`` and ``artifacts/`` — the profile's resource files, plus
      ``.claude/skills/<name>/`` symlinks back to the canonical ``skills/`` tree.
    - ``.aw/profile/`` — the full profile payload, plus a ``ref.json`` recording
      provenance (the source-blueprint triple for a blueprint copy; omitted for a profile
      created fresh on the shelf, leaving just the profile triple).
    """
    by_path = {f["path"]: f for f in files}
    doc = yaml.safe_load(by_path["profile.yaml"]["content_utf8"]) or {}
    instructions_path = str(doc.get("instructions") or "instructions.md")
    instructions = by_path[instructions_path]["content_utf8"] if instructions_path in by_path else ""
    provenance = (
        f"blueprint {source_blueprint_ref} v{source_blueprint_version}"
        if source_blueprint_ref
        else "created"
    )

    ref: dict[str, str] = {
        "profile_digest": profile_digest,
        "profile_ref": profile_ref,
        "profile_version": profile_version,
    }
    if source_blueprint_ref:
        ref["source_blueprint_digest"] = source_blueprint_digest or ""
        ref["source_blueprint_ref"] = source_blueprint_ref
        ref["source_blueprint_version"] = source_blueprint_version or ""

    entries: list[dict[str, str]] = [
        {
            "path": "AGENTS.md",
            "kind": "file",
            "content_utf8": _compose_agents_md(
                doc, profile_ref=profile_ref, instructions=instructions, provenance=provenance
            ),
        },
        {"path": "CLAUDE.md", "kind": "symlink", "target": "AGENTS.md"},
    ]

    # Canonical resource files at the home root, plus per-harness skill symlinks.
    resource_paths = [str(skill["path"]) for skill in doc.get("skills") or []]
    resource_paths += [str(artifact["path"]) for artifact in doc.get("artifacts") or []]
    for path in resource_paths:
        entries.append({"path": path, "kind": "file", "content_utf8": by_path[path]["content_utf8"]})
    for skill in doc.get("skills") or []:
        skill_rel = str(skill["path"])
        link_path = f".claude/{skill_rel}"
        target = "../" * link_path.count("/") + skill_rel
        entries.append({"path": link_path, "kind": "symlink", "target": target})

    # The full profile payload under .aw/profile/, plus the provenance ref.json.
    for f in files:
        entries.append({"path": f".aw/profile/{f['path']}", "kind": "file", "content_utf8": f["content_utf8"]})
    entries.append(
        {
            "path": ".aw/profile/ref.json",
            "kind": "file",
            "content_utf8": json.dumps(ref, indent=2, sort_keys=True) + "\n",
        }
    )

    entries.sort(key=lambda entry: entry["path"])
    return entries
