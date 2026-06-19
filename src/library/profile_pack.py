"""Pure profile-pack interpretation.

Parse an import payload (``aweb.profile-pack.import-payload.v1``) into pack +
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
from library.digest import PACK_PAYLOAD_SCHEMA, PROFILE_PAYLOAD_SCHEMA, payload_digest

# Structured-field parts tracked for the per-part update-from-source merge (files
# are tracked per-file). "instructions" lives in instructions.md (a file part).
_BASELINE_FIELDS = ("mission", "accepted_work", "runtime_assumptions", "memory_policy")


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
class ParsedPack:
    pack_ref: str
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


def _profile_payload_files(pack_files: list[dict[str, str]], profile_id: str) -> list[dict[str, str]]:
    """The profile's files re-relativized to PROFILE-relative paths (the form the
    profile digest hashes)."""
    prefix = f"profiles/{profile_id}/"
    out = [
        {"content_utf8": f["content_utf8"], "path": f["path"][len(prefix) :], "sha256": f["sha256"]}
        for f in pack_files
        if f["path"].startswith(prefix)
    ]
    out.sort(key=lambda f: f["path"])
    return out


def parse_import_payload(payload: dict[str, Any]) -> ParsedPack:
    """Validate and parse an import-payload.v1 into a pack + profiles with digests."""
    if not isinstance(payload, dict) or payload.get("schema") != PACK_PAYLOAD_SCHEMA:
        raise ValueError(f"import payload schema must be {PACK_PAYLOAD_SCHEMA}")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("import payload must contain files")
    if not all(isinstance(f, dict) and {"content_utf8", "path", "sha256"} <= set(f) for f in files):
        raise ValueError("import payload files must have content_utf8, path, sha256")

    by_path = {f["path"]: f for f in files}
    if "pack.yaml" not in by_path:
        raise ValueError("import payload missing pack.yaml")
    pack_yaml = yaml.safe_load(by_path["pack.yaml"]["content_utf8"]) or {}
    pack_ref = str(pack_yaml["id"])
    pack_version = str(pack_yaml["version"])
    recommendations = pack_yaml.get("profiles") or []

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

    return ParsedPack(
        pack_ref=pack_ref,
        version=pack_version,
        digest=payload_digest(files, PACK_PAYLOAD_SCHEMA),
        name=str(pack_yaml.get("name") or pack_ref),
        summary=pack_yaml.get("summary"),
        description=pack_yaml.get("description"),
        recommendations=list(recommendations),
        runtime_hints=_as_str_list(pack_yaml.get("runtime_hints")),
        expected_apps=_as_str_list(pack_yaml.get("expected_apps")),
        first_mission_examples=_as_str_list(pack_yaml.get("first_mission_examples")),
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


def part_baselines(profile: ParsedProfile) -> dict[str, str]:
    """Per-part content digests recorded at copy/sync, for the per-part 3-way merge.
    Parts = each file (its sha256) + each structured field (sha256 of its canonical
    bytes). Keys are namespaced ('file:<path>' / 'field:<name>')."""
    baselines = {f"file:{entry['path']}": entry["sha256"] for entry in profile.files}
    for field in _BASELINE_FIELDS:
        value = getattr(profile, field)
        baselines[f"field:{field}"] = "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
    return baselines


def import_return(pack: ParsedPack) -> dict[str, Any]:
    """The POST /v1/profile-packs/import response body."""
    return {
        "digest": pack.digest,
        "pack_ref": pack.pack_ref,
        "version": pack.version,
        "profiles": [
            {"profile_ref": profile.profile_ref, "version": profile.version, "digest": profile.digest}
            for profile in pack.profiles
        ],
    }


def materialize_home_files(
    profile: ParsedProfile,
    *,
    source_profile_pack_ref: str,
    source_profile_pack_version: str,
    source_profile_pack_digest: str,
) -> list[dict[str, str]]:
    """The home layout a runtime materialization writes: the profile's content
    files (minus profile.yaml metadata) plus .aw/profile/ref.json, home-relative."""
    ref = {
        "profile_ref": profile.profile_ref,
        "profile_version": profile.version,
        "profile_digest": profile.digest,
        "source_profile_pack_ref": source_profile_pack_ref,
        "source_profile_pack_version": source_profile_pack_version,
        "source_profile_pack_digest": source_profile_pack_digest,
    }
    home_files = [
        {"path": f["path"], "content_utf8": f["content_utf8"]}
        for f in profile.files
        if f["path"] != "profile.yaml"
    ]
    home_files.append(
        {"path": ".aw/profile/ref.json", "content_utf8": json.dumps(ref, indent=2, sort_keys=True) + "\n"}
    )
    home_files.sort(key=lambda f: f["path"])
    return home_files
