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

from library.digest import PACK_PAYLOAD_SCHEMA, collect_files
from library.profile_pack import (
    ParsedPack,
    build_pack_payload,
    import_return,
    parse_import_payload,
    parse_profile_payload,
)

pytestmark = pytest.mark.e2e

_FIXTURE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering"
_SOURCE = _FIXTURE / "source"
_EXPECTED = _FIXTURE / "expected"
_MANIFEST_SHA256 = "b795e1bb614130893610947b4b008ec6adf577fc17ddcd149b225209cb966213"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _json_body(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _sha(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _canonical_payload() -> dict[str, Any]:
    return _load_json(_EXPECTED / "import-payload.canonical.json")


def _payload_pack(payload: dict[str, Any]) -> ParsedPack:
    return parse_import_payload(payload)


def _fixture_pack() -> ParsedPack:
    return parse_import_payload({"files": collect_files(_SOURCE), "schema": PACK_PAYLOAD_SCHEMA})


def _expected_import_return() -> dict[str, Any]:
    payload = _load_json(_EXPECTED / "import-return.json")
    assert isinstance(payload, dict)
    return payload


def _profile_from_pack(pack: ParsedPack, profile_ref: str) -> dict[str, str]:
    for profile in pack.profiles:
        if profile.profile_ref == profile_ref:
            return {"profile_ref": profile.profile_ref, "version": profile.version, "digest": profile.digest}
    raise AssertionError(f"pack missing profile {profile_ref!r}")


def _profile_payload_files(profile_ref: str) -> list[dict[str, str]]:
    profile = next(profile for profile in _fixture_pack().profiles if profile.profile_ref == profile_ref)
    return list(profile.files)


def _expected_pack_summary(pack: ParsedPack, *, tags: list[str]) -> dict[str, Any]:
    return {
        "pack_ref": pack.pack_ref,
        "version": pack.version,
        "digest": pack.digest,
        "tags": tags,
        "name": pack.name,
        "summary": pack.summary,
        "description": pack.description,
        "recommendations": pack.recommendations,
        "runtime_hints": pack.runtime_hints,
        "expected_apps": pack.expected_apps,
        "first_mission_examples": pack.first_mission_examples,
    }


def _expected_pack_detail(pack: ParsedPack, *, tags: list[str]) -> dict[str, Any]:
    detail = _expected_pack_summary(pack, tags=tags)
    detail["profiles"] = [
        {
            "profile_ref": profile.profile_ref,
            "version": profile.version,
            "digest": profile.digest,
            "name": profile.name,
            "mission": profile.mission,
        }
        for profile in sorted(pack.profiles, key=lambda item: item.profile_ref)
    ]
    return detail


def _expected_pack_profile(pack: ParsedPack, profile_ref: str) -> dict[str, Any]:
    profile = next(profile for profile in pack.profiles if profile.profile_ref == profile_ref)
    return {
        "pack_ref": pack.pack_ref,
        "pack_version": pack.version,
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "name": profile.name,
        "mission": profile.mission,
        "accepted_work": profile.accepted_work,
        "runtime_assumptions": profile.runtime_assumptions,
        "memory_policy": profile.memory_policy,
        "expected_apps": profile.expected_apps,
        "event_subscriptions": profile.event_subscriptions,
        "approval_required": profile.approval_required,
        "files": profile.files,
    }


def _expected_shelf_profile(
    pack: ParsedPack,
    profile_ref: str,
    *,
    tags: list[str],
    source: bool = True,
) -> dict[str, Any]:
    profile = next(profile for profile in pack.profiles if profile.profile_ref == profile_ref)
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
                "source_profile_pack_ref": pack.pack_ref,
                "source_profile_pack_version": pack.version,
                "source_profile_pack_digest": pack.digest,
                "source_profile_ref": profile.profile_ref,
                "source_profile_version": profile.version,
                "source_profile_digest": profile.digest,
            }
        )
    else:
        base.update(
            {
                "source_profile_pack_ref": None,
                "source_profile_pack_version": None,
                "source_profile_pack_digest": None,
                "source_profile_ref": None,
                "source_profile_version": None,
                "source_profile_digest": None,
            }
        )
    return base


def _expected_shelf_read_profile(pack: ParsedPack, profile_ref: str, *, tags: list[str], update_available: bool) -> dict[str, Any]:
    profile = next(profile for profile in pack.profiles if profile.profile_ref == profile_ref)
    return {
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "name": profile.name,
        "summary": profile.mission,
        "tags": tags,
        "source_profile_pack_ref": pack.pack_ref,
        "source_profile_pack_version": pack.version,
        "source_profile_pack_digest": pack.digest,
        "source_profile_ref": profile.profile_ref,
        "source_profile_version": profile.version,
        "source_pack_latest_version": "0.2.0" if update_available else pack.version,
        "update_available": update_available,
    }


def _expected_home_entries(profile_ref: str, *, created: bool = False, pack: ParsedPack | None = None) -> list[dict[str, str]]:
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
    if pack is not None:
        fixture_pack = _fixture_pack()
        for entry in entries:
            if entry["kind"] == "file":
                entry["content_utf8"] = (
                    entry["content_utf8"]
                    .replace(fixture_pack.pack_ref, pack.pack_ref)
                    .replace(fixture_pack.digest, pack.digest)
                )
    return entries


def _pack_payload(*, pack_ref: str, pack_version: str = "0.1.0", mutate_developer: bool = False) -> dict[str, Any]:
    files = [dict(file) for file in _canonical_payload()["files"]]
    for file in files:
        if file["path"] == "pack.yaml":
            doc = yaml.safe_load(file["content_utf8"])
            doc["id"] = pack_ref
            doc["version"] = pack_version
            file["content_utf8"] = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            file["sha256"] = _sha(file["content_utf8"])
        if mutate_developer and file["path"] == "profiles/developer/instructions.md":
            file["content_utf8"] += "\nAlways mention the updated pack version.\n"
            file["sha256"] = _sha(file["content_utf8"])
    files.sort(key=lambda entry: entry["path"])
    return {"files": files, "schema": PACK_PAYLOAD_SCHEMA}


def _profile_files_with_version(profile_ref: str, version: str) -> list[dict[str, str]]:
    files = [dict(file) for file in _profile_payload_files(profile_ref)]
    for file in files:
        if file["path"] == "profile.yaml":
            doc = yaml.safe_load(file["content_utf8"])
            doc["version"] = version
            doc["mission"] = f"{doc['mission']} Updated in a private shelf version."
            file["content_utf8"] = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            file["sha256"] = _sha(file["content_utf8"])
    files.sort(key=lambda entry: entry["path"])
    return files


def _post_json(team: Any, url: str, payload: Any) -> subprocess.CompletedProcess[str]:
    return _aw_request(team, "POST", url, body=_json_body(payload))


def _put_json(team: Any, url: str, payload: Any) -> subprocess.CompletedProcess[str]:
    return _aw_request(team, "PUT", url, body=_json_body(payload))


def _publish_pack(team: Any, library: RunningLibrary, payload: dict[str, Any]) -> dict[str, Any]:
    pack = _payload_pack(payload)
    result = _aw_json(
        _post_json(team, f"{library.origin}/v1/profile-packs/import", payload),
        context=f"publish pack {pack.pack_ref}",
    )
    assert result == import_return(pack)
    return result


def _import_to_shelf(
    team: Any,
    library: RunningLibrary,
    *,
    pack: ParsedPack,
    profile_ref: str = "developer",
    tags: list[str] | None = None,
    created: bool = True,
) -> dict[str, Any]:
    profile = next(profile for profile in pack.profiles if profile.profile_ref == profile_ref)
    response = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/shelf/import",
            {
                "source_profile_pack_ref": pack.pack_ref,
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
        "source_profile_pack_ref": pack.pack_ref,
        "source_profile_pack_version": pack.version,
        "source_profile_pack_digest": pack.digest,
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


def test_manifest_digest_and_public_pack_catalog_reads_are_unauth(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    manifest = httpx.get(f"{library.origin}/aweb-app.json", timeout=10.0)
    assert manifest.status_code == 200, manifest.text
    assert hashlib.sha256(manifest.content).hexdigest() == _MANIFEST_SHA256

    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    payload = _pack_payload(pack_ref=f"aweb.e2e-{unique}-pack")
    pack = _payload_pack(payload)
    _publish_pack(team, library, payload)

    tags = _aw_json(
        _put_json(
            team,
            f"{library.origin}/v1/profile-packs/{pack.pack_ref}/tags",
            {"tags": [f"E2E-{unique}", "Starter", "starter"]},
        ),
        context="set pack tags",
    )
    assert tags == {"pack_ref": pack.pack_ref, "tags": [f"e2e-{unique}", "starter"]}

    catalog = httpx.get(f"{library.origin}/v1/profile-packs", params={"tags": f"e2e-{unique}"}, timeout=10.0)
    assert catalog.status_code == 200, catalog.text
    assert catalog.json() == [_expected_pack_summary(pack, tags=[f"e2e-{unique}", "starter"])]

    missing = httpx.get(f"{library.origin}/v1/profile-packs", params={"tags": "missing"}, timeout=10.0)
    assert missing.status_code == 200, missing.text
    assert all(item["pack_ref"] != pack.pack_ref for item in missing.json())

    detail = httpx.get(f"{library.origin}/v1/profile-packs/{pack.pack_ref}", timeout=10.0)
    assert detail.status_code == 200, detail.text
    assert detail.json() == _expected_pack_detail(pack, tags=[f"e2e-{unique}", "starter"])

    preview = httpx.get(f"{library.origin}/v1/profile-packs/{pack.pack_ref}/profiles/developer", timeout=10.0)
    assert preview.status_code == 200, preview.text
    assert preview.json() == _expected_pack_profile(pack, "developer")


def test_publish_pack_preserves_frozen_import_contract(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    result = _publish_pack(team, library, _canonical_payload())
    assert result == _expected_import_return()


def test_import_to_shelf_idempotent_conflict_never_clobbers_and_signals_update(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    pack_payload = _pack_payload(pack_ref=f"aweb.copy-{unique}")
    pack = _payload_pack(pack_payload)
    _publish_pack(team, library, pack_payload)

    _import_to_shelf(team, library, pack=pack, tags=["First", "first"])
    shelf = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf")
    assert shelf == {"profiles": [_expected_shelf_read_profile(pack, "developer", tags=["first"], update_available=False)]}

    updated_tags = _aw_json(
        _put_json(team, f"{library.origin}/v1/profiles/developer/tags", {"tags": ["local", "first"]}),
        context="set shelf profile tags",
    )
    assert updated_tags == {"profile_ref": "developer", "tags": ["first", "local"]}

    # Same source profile is a pure no-op and never clobbers local shelf metadata.
    _import_to_shelf(team, library, pack=pack, tags=["ignored"], created=False)
    shelf_after_noop = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf after noop")
    assert shelf_after_noop["profiles"][0]["tags"] == ["first", "local"]
    assert shelf_after_noop["profiles"][0]["update_available"] is False

    # Publishing a newer source pack version does not auto-update the shelf copy;
    # the read only exposes update_available until a future update-from-source act.
    newer_payload = _pack_payload(pack_ref=pack.pack_ref, pack_version="0.2.0", mutate_developer=True)
    _publish_pack(team, library, newer_payload)
    _import_to_shelf(team, library, pack=pack, created=False)
    shelf_with_update = _aw_json(_aw_request(team, "GET", f"{library.origin}/v1/shelf"), context="list shelf with update")
    assert shelf_with_update == {
        "profiles": [_expected_shelf_read_profile(pack, "developer", tags=["first", "local"], update_available=True)]
    }

    # Same target shelf ref from a different source pack is a conflict.
    other_payload = _pack_payload(pack_ref=f"aweb.other-{unique}")
    other_pack = _payload_pack(other_payload)
    _publish_pack(team, library, other_payload)
    conflict = _post_json(
        team,
        f"{library.origin}/v1/shelf/import",
        {"source_profile_pack_ref": other_pack.pack_ref, "profile_ref": "developer"},
    )
    _assert_aw_status(conflict, 409, context="different source same shelf ref")


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
    direct_pack = _fixture_pack()
    assert created == _expected_shelf_profile(direct_pack, "developer", tags=["direct"], source=False)

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
        "source_profile_pack_ref": None,
        "source_profile_pack_version": None,
        "source_profile_pack_digest": None,
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
    assert versioned["source_profile_pack_ref"] is None

    unique = uuid.uuid4().hex[:8]
    publish_request = {
        "profile_version": "0.1.0",
        "pack_version": "1.0.0",
        "new_pack": {
            "pack_ref": f"aweb.published-{unique}",
            "name": "Published E2E Pack",
            "summary": "Published from a private shelf profile.",
            "description": "Round-trip digest proof.",
            "tags": ["Published", f"E2E-{unique}"],
            "readme": "# Published E2E Pack\n",
            "missions": ["Use the published profile."],
        },
    }
    published = _aw_json(
        _post_json(team, f"{library.origin}/v1/profiles/developer/publish", publish_request),
        context="publish shelf profile into new pack",
    )
    expected_payload = build_pack_payload(
        pack_ref=publish_request["new_pack"]["pack_ref"],
        pack_version="1.0.0",
        name="Published E2E Pack",
        summary="Published from a private shelf profile.",
        description="Round-trip digest proof.",
        first_mission_examples=["Use the published profile."],
        readme="# Published E2E Pack\n",
        prior_files=None,
        profile_ref="developer",
        profile_files=_profile_payload_files("developer"),
    )
    expected_pack = parse_import_payload(expected_payload)
    assert published == {
        "pack_ref": expected_pack.pack_ref,
        "pack_version": expected_pack.version,
        "pack_digest": expected_pack.digest,
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": created["digest"],
    }
    assert published["pack_digest"] == import_return(expected_pack)["digest"]

    public_pack = httpx.get(
        f"{library.origin}/v1/profile-packs",
        params={"tags": f"e2e-{unique}"},
        timeout=10.0,
    )
    assert public_pack.status_code == 200, public_pack.text
    assert public_pack.json() == [_expected_pack_summary(expected_pack, tags=[f"e2e-{unique}", "published"])]

    existing_publish = _aw_json(
        _post_json(
            team,
            f"{library.origin}/v1/profiles/developer/publish",
            {"profile_version": "0.1.0", "pack_version": "1.0.1", "target_pack_ref": expected_pack.pack_ref},
        ),
        context="publish shelf profile into existing pack",
    )
    assert existing_publish["pack_ref"] == expected_pack.pack_ref
    assert existing_publish["pack_version"] == "1.0.1"
    assert existing_publish["profile_digest"] == created["digest"]

    invalid_target = _post_json(
        team,
        f"{library.origin}/v1/profiles/developer/publish",
        {
            "profile_version": "0.1.0",
            "pack_version": "1.0.2",
            "target_pack_ref": expected_pack.pack_ref,
            "new_pack": {"pack_ref": f"aweb.invalid-{unique}", "name": "Invalid"},
        },
    )
    _assert_aw_status(invalid_target, 422, context="publish target XOR new_pack")


def test_register_bind_materialize_pack_copy_and_proposals(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    unique = uuid.uuid4().hex[:8]
    payload = _pack_payload(pack_ref=f"aweb.flow-{unique}")
    pack = _payload_pack(payload)
    _publish_pack(team, library, payload)
    shelf_copy = _import_to_shelf(team, library, pack=pack)

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
        context="materialize bound pack-copy profile",
    )
    inspect_profile = next(profile for profile in _fixture_pack().profiles if profile.profile_ref == "developer")
    assert materialized == {
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": binding["profile_digest"],
        "source_profile_pack_ref": pack.pack_ref,
        "source_profile_pack_version": pack.version,
        "source_profile_pack_digest": pack.digest,
        "runtime_assumptions": inspect_profile.runtime_assumptions,
        "memory_policy": inspect_profile.memory_policy,
        "home_files": _expected_home_entries("developer", pack=pack),
    }
    assert any(entry == {"path": "CLAUDE.md", "kind": "symlink", "target": "AGENTS.md"} for entry in materialized["home_files"])
    ref_entry = next(entry for entry in materialized["home_files"] if entry["path"] == ".aw/profile/ref.json")
    ref = json.loads(ref_entry["content_utf8"])
    assert ref == {
        "profile_ref": "developer",
        "profile_version": "0.1.0",
        "profile_digest": binding["profile_digest"],
        "source_profile_pack_ref": pack.pack_ref,
        "source_profile_pack_version": pack.version,
        "source_profile_pack_digest": pack.digest,
    }

    def assert_proposal_shape(proposal: dict[str, Any], *, status: str, content: dict[str, Any]) -> None:
        assert set(proposal) == {
            "proposal_id",
            "target",
            "profile_ref",
            "profile_version",
            "status",
            "content",
            "created_by_alias",
            "created_at",
        }
        assert isinstance(proposal["proposal_id"], str)
        assert proposal["target"] == "profile"
        assert proposal["profile_ref"] == "developer"
        assert proposal["profile_version"] == "0.1.0"
        assert proposal["status"] == status
        assert proposal["content"] == content
        assert proposal["created_by_alias"] == team.alias
        assert isinstance(proposal["created_at"], str)

    def create_proposal(title: str) -> tuple[dict[str, Any], dict[str, Any]]:
        content = {
            "title": title,
            "summary": "Learned improvement from completed repo work.",
            "changes": [
                {
                    "path": "instructions.md",
                    "operation": "append",
                    "content_utf8": "\n- Include concise test evidence in every handoff.\n",
                }
            ],
        }
        proposal = _aw_json(
            _post_json(
                team,
                f"{library.origin}/v1/proposals",
                {
                    "target": "profile",
                    "profile_ref": "developer",
                    "profile_version": "0.1.0",
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


def test_empty_profile_invariant_never_requires_reachable_library(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    expected = _load_json(_EXPECTED / "empty-profile-invariant.json")
    assert expected == {
        "schema": "aweb.profile-pack.empty-profile-invariant.v1",
        "library_unreachable": True,
        "team_create": {
            "default_profile": "empty",
            "must_succeed_without_library": True,
            "profile_pack_required": False,
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
    unauth_publish = httpx.post(f"{library.origin}/v1/profile-packs/import", json=payload, timeout=10.0)
    assert unauth_publish.status_code == 401, unauth_publish.text
    unauth_register = httpx.post(f"{library.origin}/v1/team/register", json={}, timeout=10.0)
    assert unauth_register.status_code == 401, unauth_register.text
    unauth_shelf = httpx.get(f"{library.origin}/v1/shelf", timeout=10.0)
    assert unauth_shelf.status_code == 401, unauth_shelf.text
    unauth_import_shelf = httpx.post(
        f"{library.origin}/v1/shelf/import",
        json={"source_profile_pack_ref": "aweb.engineering-pack", "profile_ref": "developer"},
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
    pack_ref = _fixture_pack().pack_ref
    for profile_ref in ("coordinator", "developer", "reviewer"):
        ref = _load_json(_EXPECTED / "materialized-home" / profile_ref / ".aw" / "profile" / "ref.json")
        assert ref["profile_ref"] == profile_ref
        assert ref["source_profile_pack_ref"] == pack_ref
    created_ref = _load_json(_EXPECTED / "materialized-home-created" / "developer" / ".aw" / "profile" / "ref.json")
    assert set(created_ref) == {"profile_digest", "profile_ref", "profile_version"}
