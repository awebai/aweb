from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from test_e2e_smoke import (
    AWWorkspace,
    RunningLibrary,
    _assert_aw_status,
    _aw_json,
    _aw_request,
    _provision_team,
)

from library.blueprint import (
    ParsedBlueprint,
    build_blueprint_payload,
    import_return,
    parse_import_payload,
    parse_profile_payload,
    profile_asset_digests,
)
from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files

pytestmark = pytest.mark.e2e

_FIXTURE = Path(__file__).parent / "vectors" / "blueprints" / "engineering"
_SOURCE = _FIXTURE / "source"
_EXPECTED = _FIXTURE / "expected"
_PROFILE_ASSET_CHANGESET_SCHEMA = "aweb.library.profile-asset-changeset.v1"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _json_body(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _sha(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _asset_changeset(*assets: dict[str, Any]) -> dict[str, Any]:
    return {"schema": _PROFILE_ASSET_CHANGESET_SCHEMA, "assets": list(assets)}


def _canonical_payload() -> dict[str, Any]:
    return _load_json(_EXPECTED / "import-payload.canonical.json")


def _payload_blueprint(payload: dict[str, Any]) -> ParsedBlueprint:
    return parse_import_payload(payload)


def _fixture_blueprint() -> ParsedBlueprint:
    return parse_import_payload({"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA})


def _expected_import_return() -> dict[str, Any]:
    payload = _load_json(_EXPECTED / "import-return.json")
    assert isinstance(payload, dict)
    return payload


def _profile_from_blueprint(blueprint: ParsedBlueprint, profile_ref: str) -> dict[str, str]:
    for profile in blueprint.profiles:
        if profile.profile_ref == profile_ref:
            return {"profile_ref": profile.profile_ref, "version": profile.version, "digest": profile.digest}
    raise AssertionError(f"blueprint missing profile {profile_ref!r}")


def _profile_payload_files(profile_ref: str) -> list[dict[str, str]]:
    profile = next(profile for profile in _fixture_blueprint().profiles if profile.profile_ref == profile_ref)
    return list(profile.files)


def _expected_blueprint_summary(blueprint: ParsedBlueprint, *, tags: list[str]) -> dict[str, Any]:
    return {
        "blueprint_ref": blueprint.blueprint_ref,
        "version": blueprint.version,
        "digest": blueprint.digest,
        "tags": tags,
        "name": blueprint.name,
        "summary": blueprint.summary,
        "description": blueprint.description,
        "recommendations": blueprint.recommendations,
        "runtime_hints": blueprint.runtime_hints,
        "expected_apps": blueprint.expected_apps,
        "first_mission_examples": blueprint.first_mission_examples,
    }


def _expected_blueprint_detail(blueprint: ParsedBlueprint, *, tags: list[str]) -> dict[str, Any]:
    detail = _expected_blueprint_summary(blueprint, tags=tags)
    detail["profiles"] = [
        {
            "profile_ref": profile.profile_ref,
            "version": profile.version,
            "digest": profile.digest,
            "name": profile.name,
            "mission": profile.mission,
        }
        for profile in sorted(blueprint.profiles, key=lambda item: item.profile_ref)
    ]
    return detail


def _runtime_hints_for_profile(blueprint: ParsedBlueprint, profile_ref: str) -> list[str]:
    for recommendation in blueprint.recommendations:
        if recommendation.get("id") == profile_ref:
            value = recommendation.get("runtime_hints")
            return [str(item) for item in value] if isinstance(value, list) else []
    return []


def _expected_blueprint_profile(blueprint: ParsedBlueprint, profile_ref: str) -> dict[str, Any]:
    profile = next(profile for profile in blueprint.profiles if profile.profile_ref == profile_ref)
    return {
        "blueprint_ref": blueprint.blueprint_ref,
        "blueprint_version": blueprint.version,
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "name": profile.name,
        "mission": profile.mission,
        "accepted_work": profile.accepted_work,
        "runtime_assumptions": profile.runtime_assumptions,
        "runtime_hints": _runtime_hints_for_profile(blueprint, profile_ref),
        "memory_policy": profile.memory_policy,
        "expected_apps": profile.expected_apps,
        "event_subscriptions": profile.event_subscriptions,
        "approval_required": profile.approval_required,
        "files": profile.files,
    }


def _expected_shelf_profile(
    blueprint: ParsedBlueprint,
    profile_ref: str,
    *,
    tags: list[str],
    source: bool = True,
) -> dict[str, Any]:
    profile = next(profile for profile in blueprint.profiles if profile.profile_ref == profile_ref)
    base = {
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "tags": tags,
        "name": profile.name,
        "mission": profile.mission,
        "accepted_work": profile.accepted_work,
        "runtime_assumptions": profile.runtime_assumptions,
        "memory_policy": profile.memory_policy,
        "expected_apps": profile.expected_apps,
    }
    if source:
        base.update(
            {
                "source_blueprint_ref": blueprint.blueprint_ref,
                "source_blueprint_version": blueprint.version,
                "source_blueprint_digest": blueprint.digest,
                "source_profile_ref": profile.profile_ref,
                "source_profile_version": profile.version,
                "source_profile_digest": profile.digest,
            }
        )
    else:
        base.update(
            {
                "source_blueprint_ref": None,
                "source_blueprint_version": None,
                "source_blueprint_digest": None,
                "source_profile_ref": None,
                "source_profile_version": None,
                "source_profile_digest": None,
            }
        )
    return base


def _expected_shelf_read_profile(blueprint: ParsedBlueprint, profile_ref: str, *, tags: list[str], update_available: bool) -> dict[str, Any]:
    profile = next(profile for profile in blueprint.profiles if profile.profile_ref == profile_ref)
    return {
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "name": profile.name,
        "summary": profile.mission,
        "tags": tags,
        "source_blueprint_ref": blueprint.blueprint_ref,
        "source_blueprint_version": blueprint.version,
        "source_blueprint_digest": blueprint.digest,
        "source_profile_ref": profile.profile_ref,
        "source_profile_version": profile.version,
        "source_blueprint_latest_version": "0.2.0" if update_available else blueprint.version,
        "update_available": update_available,
    }


def _expected_home_entries(profile_ref: str, *, created: bool = False, blueprint: ParsedBlueprint | None = None) -> list[dict[str, str]]:
    root_name = "materialized-home-created" if created else "materialized-home"
    root = _EXPECTED / root_name / profile_ref
    entries: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": "symlink",
                    "target": str(path.readlink()),
                }
            )
        elif path.is_file():
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": "file",
                    "content_utf8": path.read_text(encoding="utf-8"),
                }
            )
    if blueprint is not None:
        fixture_blueprint = _fixture_blueprint()
        for entry in entries:
            if entry["kind"] == "file":
                entry["content_utf8"] = (
                    entry["content_utf8"]
                    .replace(fixture_blueprint.blueprint_ref, blueprint.blueprint_ref)
                    .replace(fixture_blueprint.digest, blueprint.digest)
                )
    return entries


def _home_file(entries: list[dict[str, Any]], path: str) -> str:
    entry = next(item for item in entries if item["path"] == path)
    assert entry["kind"] == "file"
    return entry["content_utf8"]


def _blueprint_payload(
    *,
    blueprint_ref: str,
    blueprint_version: str = "0.1.0",
    mutate_developer: bool = False,
    coordinator_mission: str | None = None,
    coordinator_instructions_suffix: str | None = None,
    profile_runtime_hints: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    files = [dict(file) for file in _canonical_payload()["files"]]
    for file in files:
        if file["path"] == "blueprint.yaml":
            doc = yaml.safe_load(file["content_utf8"])
            doc["id"] = blueprint_ref
            doc["version"] = blueprint_version
            if profile_runtime_hints is not None:
                for recommendation in doc.get("profiles") or []:
                    profile_id = str(recommendation.get("id") or "")
                    if profile_id in profile_runtime_hints:
                        recommendation["runtime_hints"] = profile_runtime_hints[profile_id]
            file["content_utf8"] = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            file["sha256"] = _sha(file["content_utf8"])
        if file["path"] == "profiles/coordinator/profile.yaml":
            doc = yaml.safe_load(file["content_utf8"])
            doc["version"] = blueprint_version
            if coordinator_mission is not None:
                doc["mission"] = coordinator_mission
            file["content_utf8"] = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            file["sha256"] = _sha(file["content_utf8"])
        if coordinator_instructions_suffix and file["path"] == "profiles/coordinator/instructions.md":
            file["content_utf8"] += coordinator_instructions_suffix
            file["sha256"] = _sha(file["content_utf8"])
        if mutate_developer and file["path"] == "profiles/developer/instructions.md":
            file["content_utf8"] += "\nAlways mention the updated blueprint version.\n"
            file["sha256"] = _sha(file["content_utf8"])
    files.sort(key=lambda entry: entry["path"])
    return {"files": files, "schema": BLUEPRINT_PAYLOAD_SCHEMA}


def _profile_files_with_changes(
    profile_ref: str,
    version: str,
    *,
    mission: str | None = None,
    instructions_suffix: str | None = None,
) -> list[dict[str, str]]:
    files = [dict(file) for file in _profile_payload_files(profile_ref)]
    for file in files:
        if file["path"] == "profile.yaml":
            doc = yaml.safe_load(file["content_utf8"])
            doc["version"] = version
            if mission is not None:
                doc["mission"] = mission
            file["content_utf8"] = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            file["sha256"] = _sha(file["content_utf8"])
        if instructions_suffix and file["path"] == "instructions.md":
            file["content_utf8"] += instructions_suffix
            file["sha256"] = _sha(file["content_utf8"])
    files.sort(key=lambda entry: entry["path"])
    return files


def _profile_files_with_version(profile_ref: str, version: str) -> list[dict[str, str]]:
    base_doc = yaml.safe_load(next(file for file in _profile_payload_files(profile_ref) if file["path"] == "profile.yaml")["content_utf8"])
    return _profile_files_with_changes(
        profile_ref,
        version,
        mission=f"{base_doc['mission']} Updated in a private shelf version.",
    )


def _post_json(team: Any, url: str, payload: Any) -> subprocess.CompletedProcess[str]:
    return _aw_request(team, "POST", url, body=_json_body(payload))


def _put_json(team: Any, url: str, payload: Any) -> subprocess.CompletedProcess[str]:
    return _aw_request(team, "PUT", url, body=_json_body(payload))


def _publish_blueprint(team: Any, library: RunningLibrary, payload: dict[str, Any]) -> dict[str, Any]:
    blueprint = _payload_blueprint(payload)
    result = _aw_json(
        _post_json(team, f"{library.origin}/v1/blueprints/import", payload),
        context=f"publish blueprint {blueprint.blueprint_ref}",
    )
    assert result == import_return(blueprint)
    return result


def _import_to_shelf(
    team: Any,
    library: RunningLibrary,
    *,
    blueprint: ParsedBlueprint,
    profile_ref: str = "developer",
    tags: list[str] | None = None,
    created: bool = True,
) -> dict[str, Any]:
    profile = next(profile for profile in blueprint.profiles if profile.profile_ref == profile_ref)
    response = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/shelf/import",
            {
                "source_blueprint_ref": blueprint.blueprint_ref,
                "profile_ref": profile_ref,
                "tags": tags or [],
            },
        ),
        context=f"import {profile_ref} to shelf",
    )
    assert response == {
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "source_profile_ref": profile.profile_ref,
        "source_profile_version": profile.version,
        "source_profile_digest": profile.digest,
        "source_blueprint_ref": blueprint.blueprint_ref,
        "source_blueprint_version": blueprint.version,
        "source_blueprint_digest": blueprint.digest,
        "created": created,
    }
    return response


def _bind_profile(
    team: Any,
    library: RunningLibrary,
    *,
    agent_id: str,
    profile_ref: str,
    profile_version: str,
    profile_digest: str,
) -> dict[str, Any]:
    binding = {
        "profile_ref": profile_ref,
        "profile_version": profile_version,
        "profile_digest": profile_digest,
    }
    set_response = _aw_json(
        _post_json(team, f"{library.origin}/v1/agents/{agent_id}/profile-binding", binding),
        context=f"bind {agent_id}",
    )
    assert set_response == {"agent_id": agent_id, **binding}
    get_response = _aw_json(
        _aw_request(team, "GET", f"{library.origin}/v1/agents/{agent_id}/profile-binding"),
        context=f"get binding {agent_id}",
    )
    assert get_response == set_response
    return set_response


def test_manifest_digest_and_public_blueprint_catalog_reads_are_unauth(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    # Drift test, not a pinned digest: the served manifest must equal the canonical
    # manifest bytes for this e2e origin. This stays green across feature merges that
    # add tools while still catching real serve/commit drift; the hosted pinned-digest
    # conformance lives at the unit level (test_app_manifest).
    from library.aweb_manifest import read_manifest_bytes

    manifest = httpx.get(f"{library.origin}/aweb-app.json", timeout=10.0)
    assert manifest.status_code == 200, manifest.text
    assert manifest.content == read_manifest_bytes(library.origin)
    assert json.loads(manifest.content)["app"]["origin"] == library.origin

    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    runtime_hints = {"coordinator": ["claude-code"], "reviewer": ["pi", "claude-code"]}
    payload = _blueprint_payload(blueprint_ref=f"aweb.e2e-{unique}-blueprint", profile_runtime_hints=runtime_hints)
    blueprint = _payload_blueprint(payload)
    _publish_blueprint(team, library, payload)

    tags = _aw_json(
        _put_json(
            team,
            f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}/tags",
            {"tags": [f"E2E-{unique}", "Starter", "starter"]},
        ),
        context="set blueprint tags",
    )
    assert tags == {"blueprint_ref": blueprint.blueprint_ref, "tags": [f"e2e-{unique}", "starter"]}

    catalog = httpx.get(f"{library.origin}/v1/blueprints", params={"tags": f"e2e-{unique}"}, timeout=10.0)
    assert catalog.status_code == 200, catalog.text
    assert catalog.json() == [_expected_blueprint_summary(blueprint, tags=[f"e2e-{unique}", "starter"])]

    missing = httpx.get(f"{library.origin}/v1/blueprints", params={"tags": "missing"}, timeout=10.0)
    assert missing.status_code == 200, missing.text
    assert all(item["blueprint_ref"] != blueprint.blueprint_ref for item in missing.json())

    detail = httpx.get(f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}", timeout=10.0)
    assert detail.status_code == 200, detail.text
    assert detail.json() == _expected_blueprint_detail(blueprint, tags=[f"e2e-{unique}", "starter"])

    preview = httpx.get(f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}/profiles/developer", timeout=10.0)
    assert preview.status_code == 200, preview.text
    assert preview.json() == _expected_blueprint_profile(blueprint, "developer")

    coordinator_preview = httpx.get(
        f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}/profiles/coordinator", timeout=10.0
    )
    assert coordinator_preview.status_code == 200, coordinator_preview.text
    assert coordinator_preview.json()["runtime_hints"] == ["claude-code"]

    reviewer_preview = httpx.get(f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}/profiles/reviewer", timeout=10.0)
    assert reviewer_preview.status_code == 200, reviewer_preview.text
    assert reviewer_preview.json()["runtime_hints"] == ["pi", "claude-code"]


def test_publish_blueprint_preserves_frozen_import_contract(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    result = _publish_blueprint(team, library, _canonical_payload())
    assert result == _expected_import_return()


def test_import_to_shelf_idempotent_conflict_never_clobbers_and_signals_update(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    blueprint_payload = _blueprint_payload(blueprint_ref=f"aweb.copy-{unique}")
    blueprint = _payload_blueprint(blueprint_payload)
    _publish_blueprint(team, library, blueprint_payload)

    _import_to_shelf(team, library, blueprint=blueprint, tags=["First", "first"])
    shelf = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf")
    assert shelf == {"profiles": [_expected_shelf_read_profile(blueprint, "developer", tags=["first"], update_available=False)]}

    updated_tags = _aw_json(
        _put_json(team, f"{library.origin}/v1/profiles/developer/tags", {"tags": ["local", "first"]}),
        context="set shelf profile tags",
    )
    assert updated_tags == {"profile_ref": "developer", "tags": ["first", "local"]}

    # Same source profile is a pure no-op and never clobbers local shelf metadata.
    _import_to_shelf(team, library, blueprint=blueprint, tags=["ignored"], created=False)
    shelf_after_noop = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf after noop")
    assert shelf_after_noop["profiles"][0]["tags"] == ["first", "local"]
    assert shelf_after_noop["profiles"][0]["update_available"] is False

    # Publishing a newer source blueprint version does not auto-update the shelf copy;
    # the read only exposes update_available until a future update-from-source act.
    newer_payload = _blueprint_payload(blueprint_ref=blueprint.blueprint_ref, blueprint_version="0.2.0", mutate_developer=True)
    _publish_blueprint(team, library, newer_payload)
    _import_to_shelf(team, library, blueprint=blueprint, created=False)
    shelf_with_update = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf with update")
    assert shelf_with_update == {
        "profiles": [_expected_shelf_read_profile(blueprint, "developer", tags=["first", "local"], update_available=True)]
    }

    # Same target shelf ref from a different source blueprint is a conflict.
    other_payload = _blueprint_payload(blueprint_ref=f"aweb.other-{unique}")
    other_blueprint = _payload_blueprint(other_payload)
    _publish_blueprint(team, library, other_payload)
    conflict = _post_json(
        team,
        f"{library.origin}/v1/shelf/import",
        {"source_blueprint_ref": other_blueprint.blueprint_ref, "profile_ref": "developer"},
    )
    _assert_aw_status(conflict, 409, context="different source same shelf ref")


def test_update_from_source_merges_noops_and_rejects_collision(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    payload = _blueprint_payload(blueprint_ref=f"aweb.update-{unique}")
    blueprint = _payload_blueprint(payload)
    _publish_blueprint(team, library, payload)
    base = _import_to_shelf(team, library, blueprint=blueprint, profile_ref="coordinator", tags=["Update"])
    assert base["version"] == "0.1.0"

    local_instructions = "\nLocal-only coordinator instruction: preserve team-specific triage notes.\n"
    local_files = _profile_files_with_changes("coordinator", "0.1.1", instructions_suffix=local_instructions)
    local_profile = parse_profile_payload(local_files)
    local = _aw_json(
        _post_json(team, f"{library.origin}/v1/profiles/coordinator/versions", {"files": local_files}),
        context="create locally evolved coordinator version",
    )
    assert local["version"] == "0.1.1"
    assert local["digest"] == local_profile.digest
    assert local["source_blueprint_version"] == "0.1.0"

    upstream_mission = "Coordinate upstream work, keep blockers visible, and preserve crisp evidence."
    upstream_instructions = "\nUpstream coordinator instruction: summarize reviewer handoffs explicitly.\n"
    newer_payload = _blueprint_payload(
        blueprint_ref=blueprint.blueprint_ref,
        blueprint_version="0.2.0",
        coordinator_mission=upstream_mission,
        coordinator_instructions_suffix=upstream_instructions,
    )
    newer_blueprint = _payload_blueprint(newer_payload)
    _publish_blueprint(team, library, newer_payload)

    update = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles/coordinator/update-from-source",
            {"target_version": "0.2.0"},
        ),
        context="update coordinator from source",
    )
    assert update["profile_ref"] == "coordinator"
    assert update["version"] == "0.2.0"
    assert update["updated_parts"] == ["field:mission"]
    assert update["preserved_parts"] == ["file:instructions.md"]
    assert update["source_blueprint_version"] == "0.2.0"
    assert update["source_blueprint_digest"] == newer_blueprint.digest

    shelf = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf after update")
    coordinator = next(profile for profile in shelf["profiles"] if profile["profile_ref"] == "coordinator")
    assert coordinator["version"] == "0.2.0"
    assert coordinator["digest"] == update["digest"]
    assert coordinator["summary"] == upstream_mission
    assert coordinator["tags"] == ["update"]
    assert coordinator["source_blueprint_ref"] == blueprint.blueprint_ref
    assert coordinator["source_blueprint_version"] == "0.2.0"
    assert coordinator["source_blueprint_digest"] == newer_blueprint.digest
    assert coordinator["source_blueprint_latest_version"] == "0.2.0"
    assert coordinator["update_available"] is False

    materialized = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/materialize",
            {"profile_ref": "coordinator", "runtime_kind": "claude-code", "target": "local"},
        ),
        context="materialize updated coordinator",
    )
    assert materialized["profile_version"] == "0.2.0"
    assert materialized["profile_digest"] == update["digest"]
    assert materialized["source_blueprint_ref"] == blueprint.blueprint_ref
    assert materialized["source_blueprint_version"] == "0.2.0"
    assert materialized["source_blueprint_digest"] == newer_blueprint.digest
    profile_yaml = yaml.safe_load(_home_file(materialized["home_files"], ".aw/profile/profile.yaml"))
    assert profile_yaml["version"] == "0.2.0"
    assert profile_yaml["mission"] == upstream_mission
    instructions = _home_file(materialized["home_files"], ".aw/profile/instructions.md")
    assert local_instructions.strip() in instructions
    assert upstream_instructions.strip() not in instructions
    ref = json.loads(_home_file(materialized["home_files"], ".aw/profile/ref.json"))
    assert ref == {
        "profile_ref": "coordinator",
        "profile_version": "0.2.0",
        "profile_digest": update["digest"],
        "source_blueprint_ref": blueprint.blueprint_ref,
        "source_blueprint_version": "0.2.0",
        "source_blueprint_digest": newer_blueprint.digest,
    }

    no_op = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles/coordinator/update-from-source",
            {"target_version": "0.2.1"},
        ),
        context="noop update coordinator from source",
    )
    assert no_op == {
        "profile_ref": "coordinator",
        "version": "0.2.0",
        "digest": update["digest"],
        "updated_parts": [],
        "preserved_parts": [],
        "source_blueprint_version": "0.2.0",
        "source_blueprint_digest": newer_blueprint.digest,
    }
    missing_noop_version = _post_json(
        team,
        f"{library.origin}/v1/materialize",
        {"profile_ref": "coordinator", "profile_version": "0.2.1", "runtime_kind": "claude-code", "target": "local"},
    )
    _assert_aw_status(missing_noop_version, 404, context="no-op does not mint target version")

    collision_payload = _blueprint_payload(
        blueprint_ref=blueprint.blueprint_ref,
        blueprint_version="0.3.0",
        coordinator_mission="Coordinate the latest upstream work without overwriting local instructions.",
        coordinator_instructions_suffix=upstream_instructions,
    )
    _publish_blueprint(team, library, collision_payload)
    collision = _post_json(
        team,
        f"{library.origin}/v1/profiles/coordinator/update-from-source",
        {"target_version": "0.1.1"},
    )
    _assert_aw_status(collision, 409, context="update-from-source target version collision")


def test_create_shelf_version_publish_profile_and_created_materialize(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    created = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles",
            {"files": _profile_payload_files("developer"), "tags": ["Direct", "direct"]},
        ),
        context="create direct shelf profile",
    )
    direct_blueprint = _fixture_blueprint()
    assert created == _expected_shelf_profile(direct_blueprint, "developer", tags=["direct"], source=False)

    binding = _bind_profile(
        team,
        library,
        agent_id="agent-created",
        profile_ref="developer",
        profile_version=created["version"],
        profile_digest=created["digest"],
    )
    materialized = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/materialize",
            {"agent_id": "agent-created", "runtime_kind": "claude-code", "target": "local"},
        ),
        context="materialize created shelf profile",
    )
    assert materialized == {
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": binding["profile_digest"],
        "source_blueprint_ref": None,
        "source_blueprint_version": None,
        "source_blueprint_digest": None,
        "runtime_assumptions": created["runtime_assumptions"],
        "memory_policy": created["memory_policy"],
        "home_files": _expected_home_entries("developer", created=True),
    }

    next_files = _profile_files_with_version("developer", "0.1.1")
    next_profile = parse_profile_payload(next_files)
    versioned = _aw_json(
        _post_json(team, f"{library.origin}/v1/profiles/developer/versions", {"files": next_files}),
        context="create shelf version",
    )
    assert versioned["profile_ref"] == "developer"
    assert versioned["version"] == "0.1.1"
    assert versioned["digest"] == next_profile.digest
    assert versioned["tags"] == ["direct"]
    assert versioned["source_blueprint_ref"] is None

    unique = uuid.uuid4().hex[:8]
    publish_request = {
        "profile_version": "0.1.0",
        "blueprint_version": "1.0.0",
        "new_blueprint": {
            "blueprint_ref": f"aweb.published-{unique}",
            "name": "Published E2E Blueprint",
            "summary": "Published from a private shelf profile.",
            "description": "Round-trip digest proof.",
            "tags": ["Published", f"E2E-{unique}"],
            "readme": "# Published E2E Blueprint\n",
            "missions": ["Use the published profile."],
        },
    }
    published = _aw_json(
        _post_json(team, f"{library.origin}/v1/profiles/developer/publish", publish_request),
        context="publish shelf profile into new blueprint",
    )
    expected_payload = build_blueprint_payload(
        blueprint_ref=publish_request["new_blueprint"]["blueprint_ref"],
        blueprint_version="1.0.0",
        name="Published E2E Blueprint",
        summary="Published from a private shelf profile.",
        description="Round-trip digest proof.",
        first_mission_examples=["Use the published profile."],
        readme="# Published E2E Blueprint\n",
        prior_files=None,
        profile_ref="developer",
        profile_files=_profile_payload_files("developer"),
    )
    expected_blueprint = parse_import_payload(expected_payload)
    assert published == {
        "blueprint_ref": expected_blueprint.blueprint_ref,
        "blueprint_version": expected_blueprint.version,
        "blueprint_digest": expected_blueprint.digest,
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": created["digest"],
    }
    assert published["blueprint_digest"] == import_return(expected_blueprint)["digest"]

    public_blueprint = httpx.get(
        f"{library.origin}/v1/blueprints",
        params={"tags": f"e2e-{unique}"},
        timeout=10.0,
    )
    assert public_blueprint.status_code == 200, public_blueprint.text
    assert public_blueprint.json() == [_expected_blueprint_summary(expected_blueprint, tags=[f"e2e-{unique}", "published"])]

    existing_publish = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles/developer/publish",
            {"profile_version": "0.1.0", "blueprint_version": "1.0.1", "target_blueprint_ref": expected_blueprint.blueprint_ref},
        ),
        context="publish shelf profile into existing blueprint",
    )
    assert existing_publish["blueprint_ref"] == expected_blueprint.blueprint_ref
    assert existing_publish["blueprint_version"] == "1.0.1"
    assert existing_publish["profile_digest"] == created["digest"]

    invalid_target = _post_json(
        team,
        f"{library.origin}/v1/profiles/developer/publish",
        {
            "profile_version": "0.1.0",
            "blueprint_version": "1.0.2",
            "target_blueprint_ref": expected_blueprint.blueprint_ref,
            "new_blueprint": {"blueprint_ref": f"aweb.invalid-{unique}", "name": "Invalid"},
        },
    )
    _assert_aw_status(invalid_target, 422, context="publish target XOR new_blueprint")


def test_register_bind_materialize_blueprint_copy_and_proposals(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    payload = _blueprint_payload(blueprint_ref=f"aweb.flow-{unique}")
    blueprint = _payload_blueprint(payload)
    _publish_blueprint(team, library, payload)
    shelf_copy = _import_to_shelf(team, library, blueprint=blueprint)

    first_register = _aw_json(_post_json(team, f"{library.origin}/v1/team/register", {}), context="team register")
    second_register = _aw_json(_post_json(team, f"{library.origin}/v1/team/register", {}), context="team register again")
    assert second_register == first_register
    assert first_register["team_id"] == team.team_id
    assert first_register["owner"] is None
    assert first_register["display_name"] is None
    assert isinstance(first_register["registered_at"], str)

    unbound_materialize = _post_json(
        team,
        f"{library.origin}/v1/materialize",
        {"agent_id": "agent-dev-1", "runtime_kind": "claude-code", "target": "local"},
    )
    _assert_aw_status(unbound_materialize, 404, context="materialize requires bound profile")

    binding = _bind_profile(
        team,
        library,
        agent_id="agent-dev-1",
        profile_ref="developer",
        profile_version=shelf_copy["version"],
        profile_digest=shelf_copy["digest"],
    )
    materialized = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/materialize",
            {"agent_id": "agent-dev-1", "runtime_kind": "claude-code", "target": "local"},
        ),
        context="materialize bound blueprint-copy profile",
    )
    inspect_profile = next(profile for profile in _fixture_blueprint().profiles if profile.profile_ref == "developer")
    assert materialized == {
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": binding["profile_digest"],
        "source_blueprint_ref": blueprint.blueprint_ref,
        "source_blueprint_version": blueprint.version,
        "source_blueprint_digest": blueprint.digest,
        "runtime_assumptions": inspect_profile.runtime_assumptions,
        "memory_policy": inspect_profile.memory_policy,
        "home_files": _expected_home_entries("developer", blueprint=blueprint),
    }
    assert any(entry == {"path": "CLAUDE.md", "kind": "symlink", "target": "AGENTS.md"} for entry in materialized["home_files"])
    ref_entry = next(entry for entry in materialized["home_files"] if entry["path"] == ".aw/profile/ref.json")
    ref = json.loads(ref_entry["content_utf8"])
    assert ref == {
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": binding["profile_digest"],
        "source_blueprint_ref": blueprint.blueprint_ref,
        "source_blueprint_version": blueprint.version,
        "source_blueprint_digest": blueprint.digest,
    }

    def assert_proposal_shape(
        proposal: dict[str, Any], *, status: str, content: dict[str, Any], minted: bool = False
    ) -> None:
        expected_keys = {
            "proposal_id",
            "target",
            "profile_ref",
            "status",
            "content",
            "summary",
            "rationale",
            "created_by_alias",
            "created_at",
        }
        if minted:
            expected_keys.add("minted")
        assert set(proposal) == expected_keys
        assert isinstance(proposal["proposal_id"], str)
        assert proposal["target"] == "memory"
        assert proposal["profile_ref"] is None
        assert proposal["status"] == status
        assert proposal["content"] == content
        assert proposal["summary"] is None
        assert proposal["rationale"] is None
        assert proposal["created_by_alias"] == team.alias
        assert isinstance(proposal["created_at"], str)

    def create_proposal(title: str) -> tuple[dict[str, Any], dict[str, Any]]:
        content = {
            "title": title,
            "summary": "Learned improvement from completed repo work.",
            "changes": [{"path": "notes/lesson.md", "operation": "append"}],
        }
        proposal = _aw_json(
            _post_json(
                team,
                f"{library.origin}/v1/proposals",
                {
                    "target": "memory",
                    "content": content,
                },
            ),
            context=f"create proposal {title}",
        )
        assert_proposal_shape(proposal, status="open", content=content)
        return proposal, content

    approve_candidate, approve_content = create_proposal("Add handoff evidence reminder")
    reject_candidate, reject_content = create_proposal("Rejected experiment")
    assert approve_candidate["proposal_id"] != reject_candidate["proposal_id"]

    listed = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/proposals"), context="list proposals")
    assert {proposal["proposal_id"]: proposal for proposal in listed} == {
        approve_candidate["proposal_id"]: approve_candidate,
        reject_candidate["proposal_id"]: reject_candidate,
    }

    approved = _aw_json(
        _post_json(team, f"{library.origin}/v1/proposals/{approve_candidate['proposal_id']}/approve", {}),
        context="approve proposal",
    )
    assert_proposal_shape(approved, status="approved", content=approve_content)
    assert "minted" not in approved
    assert approved == {**approve_candidate, "status": "approved"}

    rejected = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/proposals/{reject_candidate['proposal_id']}/reject",
            {"reason": "Not broadly useful."},
        ),
        context="reject proposal",
    )
    assert_proposal_shape(rejected, status="rejected", content=reject_content)
    assert rejected == {**reject_candidate, "status": "rejected"}


def test_profile_proposal_approval_mints_and_rejects_stale_asset(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    payload = _blueprint_payload(blueprint_ref=f"aweb.mint-{unique}")
    blueprint = _payload_blueprint(payload)
    _publish_blueprint(team, library, payload)
    base = _import_to_shelf(team, library, blueprint=blueprint, profile_ref="coordinator")

    base_profile = _aw_json(
        _aw_request(team, "GET", f"{library.origin}/v1/blueprints/{blueprint.blueprint_ref}/profiles/coordinator"),
        context="get coordinator profile for asset digests",
    )
    base_files = base_profile["files"]
    base_asset_digests = profile_asset_digests(base_files)
    base_mission = next(file for file in base_files if file["path"] == "profile.yaml")["content_utf8"]
    base_mission = (yaml.safe_load(base_mission) or {})["mission"]
    minted_mission = f"{base_mission} Updated in an asset-scoped proposal."
    minted_files = _profile_files_with_changes("coordinator", "0.1.1", mission=minted_mission)
    minted_profile = parse_profile_payload(minted_files)
    minted_content = _asset_changeset(
        {
            "path": "profile.yaml#mission",
            "content": minted_mission,
            "base_asset_digest": base_asset_digests["field:mission"],
        }
    )

    def assert_profile_proposal_shape(
        proposal: dict[str, Any], *, status: str, content: dict[str, Any], minted: bool = False
    ) -> None:
        expected_keys = {
            "proposal_id",
            "target",
            "profile_ref",
            "status",
            "content",
            "summary",
            "rationale",
            "created_by_alias",
            "created_at",
        }
        if minted:
            expected_keys.add("minted")
        assert set(proposal) == expected_keys
        assert isinstance(proposal["proposal_id"], str)
        assert proposal["target"] == "profile"
        assert proposal["profile_ref"] == "coordinator"
        assert proposal["content"] == content
        assert proposal["created_by_alias"] == team.alias
        assert isinstance(proposal["created_at"], str)
        assert proposal["status"] == status

    proposal = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/proposals",
            {
                "target": "profile",
                "profile_ref": "coordinator",
                "content": minted_content,
                "summary": "Sharpen coordinator mission",
                "rationale": "The team learned a better coordination habit.",
            },
        ),
        context="create minting proposal",
    )
    assert_profile_proposal_shape(proposal, status="open", content=minted_content)
    assert proposal["summary"] == "Sharpen coordinator mission"
    assert proposal["rationale"] == "The team learned a better coordination habit."

    approved = _aw_json(
        _post_json(team, f"{library.origin}/v1/proposals/{proposal['proposal_id']}/approve", {}),
        context="approve minting proposal",
    )
    assert_profile_proposal_shape(approved, status="approved", content=minted_content, minted=True)
    assert approved["minted"] == {
        "profile_ref": "coordinator",
        "version": "0.1.1",
        "digest": minted_profile.digest,
        "supersedes_profile_version": base["version"],
        "supersedes_profile_digest": base["digest"],
    }

    shelf = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf after mint")
    coordinator = next(profile for profile in shelf["profiles"] if profile["profile_ref"] == "coordinator")
    assert coordinator["version"] == "0.1.1"
    assert coordinator["digest"] == minted_profile.digest
    assert coordinator["source_blueprint_ref"] == blueprint.blueprint_ref

    upstream_payload = _blueprint_payload(
        blueprint_ref=blueprint.blueprint_ref,
        blueprint_version="0.2.0",
        coordinator_mission="Upstream blueprint mission should not overwrite the blessed team mission.",
    )
    _publish_blueprint(team, library, upstream_payload)
    no_pull = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles/coordinator/update-from-source",
            {"target_version": "0.2.0"},
        ),
        context="update-from-source preserves blessed proposal asset",
    )
    assert no_pull["version"] == "0.1.1"
    assert no_pull["digest"] == minted_profile.digest
    assert no_pull["updated_parts"] == []
    assert no_pull["preserved_parts"] == ["field:mission"]

    stale_content = _asset_changeset(
        {
            "path": "profile.yaml#mission",
            "content": "A stale edit based on the old mission.",
            "base_asset_digest": base_asset_digests["field:mission"],
        }
    )
    stale_proposal = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/proposals",
            {
                "target": "profile",
                "profile_ref": "coordinator",
                "content": stale_content,
            },
        ),
        context="create stale-asset proposal",
    )
    stale_approve = _post_json(
        team,
        f"{library.origin}/v1/proposals/{stale_proposal['proposal_id']}/approve",
        {},
    )
    _assert_aw_status(stale_approve, 409, context="approve stale-asset proposal")


def test_empty_profile_invariant_never_requires_reachable_library(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    expected = _load_json(_EXPECTED / "empty-profile-invariant.json")
    assert expected == {
        "schema": "aweb.blueprint.empty-profile-invariant.v1",
        "library_unreachable": True,
        "team_create": {
            "default_profile": "empty",
            "must_succeed_without_library": True,
            "blueprint_required": False,
        },
        "agent_add": {
            "default_profile": "empty",
            "must_succeed_without_library": True,
            "profile_binding_required": False,
        },
        "materialize": {"requires_bound_profile": True, "empty_profile_is_not_error": True},
    }

    aw_workspace.env.update(
        {
            "AWEB_URL": "http://127.0.0.1:1",
            "LIBRARY_URL": "http://127.0.0.1:1",
            "AWEBAI_LIBRARY_URL": "http://127.0.0.1:1",
        }
    )
    library.proxy.last_request = None
    team = _provision_team(aw_workspace)
    assert team.team_id
    assert library.proxy.last_request is None


def test_team_scoped_writes_require_real_team_cert(library: RunningLibrary) -> None:
    payload = _canonical_payload()
    unauth_publish = httpx.post(f"{library.origin}/v1/blueprints/import", json=payload, timeout=10.0)
    assert unauth_publish.status_code == 401, unauth_publish.text
    unauth_register = httpx.post(f"{library.origin}/v1/team/register", json={}, timeout=10.0)
    assert unauth_register.status_code == 401, unauth_register.text
    unauth_shelf = httpx.get(f"{library.origin}/v1/shelf", timeout=10.0)
    assert unauth_shelf.status_code == 401, unauth_shelf.text
    unauth_import_shelf = httpx.post(
        f"{library.origin}/v1/shelf/import",
        json={"source_blueprint_ref": "aweb.engineering", "profile_ref": "developer"},
        timeout=10.0,
    )
    assert unauth_import_shelf.status_code == 401, unauth_import_shelf.text
    unauth_profile_tags = httpx.put(
        f"{library.origin}/v1/profiles/developer/tags",
        json={"tags": ["implementation"]},
        timeout=10.0,
    )
    assert unauth_profile_tags.status_code == 401, unauth_profile_tags.text


def test_contract_fixture_contains_materialized_profile_refs() -> None:
    blueprint_ref = _fixture_blueprint().blueprint_ref
    for profile_ref in ("coordinator", "developer", "reviewer"):
        ref = _load_json(_EXPECTED / "materialized-home" / profile_ref / ".aw" / "profile" / "ref.json")
        assert ref["profile_ref"] == profile_ref
        assert ref["source_blueprint_ref"] == blueprint_ref
    created_ref = _load_json(_EXPECTED / "materialized-home-created" / "developer" / ".aw" / "profile" / "ref.json")
    assert set(created_ref) == {"profile_digest", "profile_ref", "profile_version"}
