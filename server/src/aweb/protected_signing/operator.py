"""Local protected-host administrator commands; no network provisioning API.

Use the host's AWEB_PROTECTED_* file settings and run as its service uid:
  python -m aweb.protected_signing.operator setup --config-dir DIR --team TEAM ...
  python -m aweb.protected_signing.operator bootstrap --requester DID_AW --contact EMAIL
  python -m aweb.protected_signing.operator check
  python -m aweb.protected_signing.operator install-controller --source-pem FILE

The last command converts an EXISTING controller seed; it never generates,
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
from .host import HostSettings, custody_slots, open_composition, validate_provisioning
from .profile import ProtectedServiceProfile


def install_controller(settings, *, profile, scope, source_pem):
    """Exclusive real-file creation in the existing private operator volume.

    The PEM's public key selects the profile binding it is pinned to; the key
    goes to that binding's private slot, the same path the serving host loads.
    """
    if os.geteuid() in settings.worker_uids:
        raise SignerRefused("custody_not_isolated")
    seed = load_signing_key_pem(read_key_file(source_pem))
    public_key = did_key_from_signing_key(seed)
    if public_key not in {binding.authority_key_did for binding in profile.bindings}:
        raise SignerRefused("authority_changed")
    _, _, slots = custody_slots(settings, profile=profile, scope=scope)
    if public_key not in slots:
        # A pinned key this host has no private slot for: the manifest names it.
        raise SignerRefused("custody_not_isolated")
    destination = slots[public_key]
    directory = os.open(
        destination.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SignerRefused("custody_not_isolated")
        fd = os.open(
            destination.name,
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
    key = sub.add_parser(
        "install-controller",
        help="Install an existing pinned private key PEM (team controller or human identity) into its binding's private slot, without overwrite",
    )
    key.add_argument("--source-pem", type=Path, required=True)
    whole = sub.add_parser(
        "setup",
        help="From a registered team to a ready signer: confirm the registry's keys, write the "
        "configuration, install the controller key, mail the first approver and provision the policy",
    )
    whole.add_argument("--config-dir", type=Path, required=True, help="Private directory setup writes the host configuration into")
    whole.add_argument("--team", required=True, help="The registered team (name:domain)")
    whole.add_argument("--human", required=True, help="The did:aw of the person who approves")
    whole.add_argument("--human-domain", help="The person's namespace (default: the team's)")
    whole.add_argument("--requester", required=True, help="The did:aw of the agent that asks for approvals")
    whole.add_argument("--contact", required=True, help="Where the approver's notices go")
    whole.add_argument("--human-origin", required=True, help="The HTTPS origin people open")
    whole.add_argument("--request-origin", required=True, help="The origin agents send requests to")
    whole.add_argument("--registry-origin", required=True, help="The registry this signer pins")
    whole.add_argument("--service-id", help="This signer's identifier (default: the human origin's host)")
    whole.add_argument("--controller-pem", type=Path, required=True, help="The existing team controller key")
    whole.add_argument("--member-pem", type=Path, required=True, help="An ordinary member key for private team reads")
    whole.add_argument("--max-active", type=int, required=True, help="Most agents one root may have in the team at once")
    whole.add_argument("--max-per-window", type=int, required=True, help="Most agents one root may add per window")
    whole.add_argument("--rate-window-seconds", type=int, default=3600, help="The window's length (default 3600)")
    whole.add_argument("--subject-kinds", default="local_agent,registered_agent", help="Agent kinds the policy admits")
    whole.add_argument("--confirm-pins", help="The fingerprint of the registry keys you checked, as setup printed it")
    return result


def setup_inputs(args):
    from awid.team_ids import parse_team_id

    from .setup import SetupInputs

    domain, _ = parse_team_id(args.team)
    return SetupInputs(
        config_dir=args.config_dir, service_id=args.service_id or args.human_origin.removeprefix("https://").split("/")[0].split(":")[0],
        team_id=args.team, human_id=args.human, human_domain=args.human_domain or domain,
        requester=args.requester, contact=args.contact, human_origin=args.human_origin,
        request_origin=args.request_origin, registry_origin=args.registry_origin,
        controller_pem=args.controller_pem, member_pem=args.member_pem,
        max_active=args.max_active, rate_window_seconds=args.rate_window_seconds, max_per_window=args.max_per_window,
        subject_kinds=tuple(kind.strip() for kind in args.subject_kinds.split(",") if kind.strip()),
        confirm_pins=args.confirm_pins,
    )


def main():
    args = parser().parse_args()
    try:
        if args.command == "setup":
            from .setup import setup

            print(json.dumps(asyncio.run(setup(setup_inputs(args)))))
            return
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
