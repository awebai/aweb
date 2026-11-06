"""Management views of pinned bytes; these reads confer no app authority."""

from dataclasses import asdict

from aweb_naapp.manifest import Manifest, ManifestError, load_manifest

from aweb.app_registry import get_installation_on, reserved_app_ids
from aweb.hook_bindings import list_app_bindings


def _changes(before, after):
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(key for key in before.keys() & after.keys() if before[key] != after[key]),
    }


def _semantic(value):
    if isinstance(value, dict):
        return {key: _semantic(item) for key, item in value.items()}
    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return sorted(value)
        return [_semantic(item) for item in value]
    return value


def semantic_diff(before: Manifest | None, after: Manifest) -> dict:
    """Compare identifiers and interpreted authority, rather than array order."""
    old = before.view() if before else {}
    new = after.view()
    old_tools = {name: _semantic(tool) for name, tool in before.tools_by_name().items()} if before else {}
    new_tools = {name: _semantic(tool) for name, tool in after.tools_by_name().items()}
    def endpoints(tools):
        return {name: {key: tool.get(key) for key in ("method", "path")} for name, tool in tools.items()}
    old_scopes, new_scopes = set(old.get("install_scopes", [])), set(new["install_scopes"])
    result = {
        "available": before is not None,
        "requested_scopes": {"added": sorted(new_scopes - old_scopes), "removed": sorted(old_scopes - new_scopes)},
        "tools": _changes(old_tools, new_tools),
        "endpoints": _changes(endpoints(old_tools), endpoints(new_tools)),
    }
    for field, identifier in (("app_keys", "kid"), ("surfaces", "id")):
        result[field] = _changes(
            {item[identifier]: _semantic(item) for item in old.get(field, [])},
            {item[identifier]: _semantic(item) for item in new[field]},
        )
    result["origin_changed"] = before is not None and before.document["app"]["origin"] != after.document["app"]["origin"]
    return result


async def pinned_manifest_on(tx, *, team_id, app_id):
    data = await tx.fetch_value(
        "SELECT manifest_bytes FROM {{tables.team_app_installs}} WHERE team_id=$1 AND app_id=$2", team_id, app_id,
    )
    if data is None:
        return None
    try:
        return load_manifest(bytes(data), reserved_names=reserved_app_ids())
    except ManifestError:
        # Older stored pins may no longer be interpretable by this reader.
        # Management and preview still report the installation and an
        # unavailable old-manifest comparison, rather than failing with 500.
        return None


async def installation_view_on(tx, *, team_id, app_id):
    record = await get_installation_on(tx, team_id=team_id, app_id=app_id)
    if record is None:
        return None
    manifest = await pinned_manifest_on(tx, team_id=team_id, app_id=app_id)
    bindings = await list_app_bindings(tx, team_id=team_id, app_id=app_id)
    return dict(
        record,
        manifest=manifest.document if manifest else None,
        resolved=manifest.view() if manifest else None,
        hook_bindings=[asdict(binding) for binding in bindings
                       if binding.installation_id == record["installation_id"] and binding.generation == record["generation"]],
        lifecycle={"declarations": manifest.view()["lifecycle"] if manifest else None,
                   "report": {"available": False}},
    )
