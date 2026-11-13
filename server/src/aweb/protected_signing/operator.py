"""Local protected-host administrator commands; no network provisioning API.

Use the host's AWEB_PROTECTED_* file settings and run as its service uid:
  python -m aweb.protected_signing.operator bootstrap --requester DID_AW --contact EMAIL
  python -m aweb.protected_signing.operator check
  python -m aweb.protected_signing.operator install-controller --source-pem FILE
  python -m aweb.protected_signing.operator bind-root --human H --root ROOT --team TEAM

The install command converts an EXISTING controller seed; it never generates,
registers, rotates or overwrites a key. No secret is printed or accepted in argv.
"""

import argparse
import asyncio
import json
import os
import stat
from pathlib import Path

from aweb_naapp.console import apply_console_migrations
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.strictjson import parse_strict
from aweb_naapp.key_file import read_key_file
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.did import did_key_from_signing_key
from awid.signing import load_signing_key_pem

from .bootstrap import initialise
from .host import HostSettings, open_composition, validate_provisioning
from .profile import ProtectedServiceProfile


def install_controller(settings, *, profile, scope, source_pem):
    """Exclusive real-file creation in the existing private operator volume."""
    if os.geteuid() in settings.worker_uids:
        raise SignerRefused("custody_not_isolated")
    seed = load_signing_key_pem(read_key_file(source_pem))
    public_key = did_key_from_signing_key(seed)
    binding = profile.binding_for(scope)
    if (
        binding.context().authority_kind != "team_controller"
        or public_key != binding.authority_key_did
    ):
        raise SignerRefused("authority_changed")
    directory = os.open(
        settings.controller_key_file.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SignerRefused("custody_not_isolated")
        fd = os.open(
            settings.controller_key_file.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=directory,
        )
        with os.fdopen(fd, "w") as stream:
            stream.write(seed.hex() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(directory)
    return {"authority_key_did": public_key}


async def run(args, settings, *, profile, scope, mailer=None, registry_transport=None):
    # Same real custody, member-key exclusion, registry pins, connection config
    # and resource cleanup as the serving host. No fixture-only composition.
    async with open_composition(
        settings,
        profile=profile,
        scope=scope,
        mailer=Mailer(EmailSettings.from_env("AWEB_PROTECTED_"))
        if mailer is None
        else mailer,
        registry_transport=registry_transport,
    ) as c:
        await c.migrate()
        await apply_console_migrations(c.db)
        if args.command == "bootstrap":
            return await initialise(c, requester=args.requester, contact=args.contact)
        await validate_provisioning(c)
        if args.command == "bind-root":
            from .root_binding import bind_root

            return await bind_root(c, human_id=args.human, root_id=args.root,
                teams=args.team, replace_root=args.replace_root)
        if args.command == "policy-init":
            from .admission import provision_policy

            return await provision_policy(c, parse_strict(args.file.read_bytes()))
        return {"provisioned": True, "service_id": c.context.service_id}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser(
        "bootstrap",
        help="Admit the first exact authorizer once, on this protected host",
    )
    bootstrap.add_argument("--requester", required=True)
    bootstrap.add_argument("--contact", required=True)
    sub.add_parser(
        "check", help="Check current custody/registry/provisioning; create no grants"
    )
    policy = sub.add_parser("policy-init", help="Provision one initial bounded policy; never replace it")
    policy.add_argument("--file", type=Path, required=True)
    binding = sub.add_parser("bind-root", help="Bind a registered root to completed H and named controller scopes; no new approval")
    binding.add_argument("--human", required=True)
    binding.add_argument("--root", required=True)
    binding.add_argument("--team", action="append", required=True)
    binding.add_argument("--replace-root")
    key = sub.add_parser(
        "install-controller",
        help="Install the existing controller PEM as a private hex-seed file, without overwrite",
    )
    key.add_argument("--source-pem", type=Path, required=True)
    return result


def main():
    args = parser().parse_args()
    try:
        settings = HostSettings()
        profile = ProtectedServiceProfile.from_json(settings.profile_file.read_bytes())
        scope = parse_strict(settings.scope_file.read_bytes())
        if args.command == "install-controller":
            result = install_controller(
                settings, profile=profile, scope=scope, source_pem=args.source_pem
            )
        else:
            result = asyncio.run(run(args, settings, profile=profile, scope=scope))
    except Exception as error:
        # Config/DB/SMTP libraries may carry DSNs, tokens or private key data in
        # exception text. Never print the raw exception or a traceback here.
        code = (
            error.code
            if isinstance(error, SignerRefused)
            else "protected_operator_failed"
        )
        print(json.dumps({"error": code}))
        raise SystemExit(1) from None
    print(json.dumps(result))


if __name__ == "__main__":
    main()
