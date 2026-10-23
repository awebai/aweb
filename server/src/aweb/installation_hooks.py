"""Translate the shared manifest's resolved hooks into pending bindings."""

from aweb.hook_bindings import HookBindingDeclaration, write_pending_bindings


async def write_manifest_bindings_on(tx, *, team_id, fetched, installation_id, generation):
    hooks = fetched.manifest.hooks or {}
    tools = fetched.manifest.tools_by_name()
    declarations = []
    for registration in hooks.get("registrations", []):
        tool = tools[registration["tool"]]
        declarations.append(HookBindingDeclaration(
            kind="registration", catalog_id=registration["catalog_id"], catalog_version=registration["catalog_version"],
            hook=registration["hook"], tool=registration["tool"], method=tool["method"], path=tool["path"],
            scopes=tuple(registration["scopes"]),
        ))
    for production in hooks.get("productions", []):
        declarations.append(HookBindingDeclaration(
            kind="production", catalog_id=production["catalog_id"], catalog_version=production["catalog_version"],
            hook=production["hook"], reads=tuple(production["reads"]),
        ))
    return await write_pending_bindings(
        tx, team_id=team_id, app_id=fetched.manifest.app_id, origin=fetched.origin, digest=fetched.digest,
        installation_id=installation_id, generation=generation, declarations=declarations,
    )
