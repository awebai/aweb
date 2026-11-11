"""Exercise cutover setup against the installed dependencies without socket I/O.

From naapp/secrets:
    uv run --frozen --no-sync python tests/check_owner_cutover_setup.py

This deliberate checker does not start PostgreSQL, SMTP, servers or browsers.
It checks all explicit constructor argument bindings in the bounded fixture
slice, then executes the cache, local composition/router, credential/certificate
and HTTPS setup that needs no remote authority. Database-derived and expanded
argument cases remain with the assigned native run; this is not that proof.
"""


def check_production_fixture_inputs(credential, origin):
    """Evaluate the real fixture expressions, then validate their local inputs.

    Registration I/O is not replaced or simulated: the exact certificate
    arguments are constructed and checked for the registry's active-alias and
    certificate-ID uniqueness requirements before opening any connection.
    """
    import ast
    import importlib
    from datetime import UTC, datetime
    from pathlib import Path
    from types import SimpleNamespace

    from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, Refused, _check_owner_act
    from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
    from aweb_naapp.runtime.installation import AdmittedInstallation
    from aweb_naapp_testing.owner_acts import TeamOwner
    from awid.team_certificate import verify_team_certificate_signature

    from tests import human_owner, production_authority, test_uninstall_cleanup

    def tree(module, function):
        return next(
            n
            for n in ast.parse(Path(module.__file__).read_text()).body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function
        )

    def call(module, function, name):
        return next(
            n
            for n in ast.walk(tree(module, function))
            if isinstance(n, ast.Call)
            and (
                isinstance(n.func, ast.Name)
                and n.func.id == name
                or isinstance(n.func, ast.Attribute)
                and n.func.attr == name
            )
        )

    def evaluate(node, module, **values):
        return eval(
            compile(ast.fix_missing_locations(ast.Expression(node)), module.__file__, "eval"),
            {**vars(module), **values},
        )

    failures = []
    registrations = 0
    for module_name, function in (
        ("tests.test_production_bootstrap", "root"),
        (
            "tests.test_production_hook_network",
            "test_production_hook_delivery_uses_explicit_dns_ca_and_internal_network",
        ),
    ):
        module = importlib.import_module(module_name)
        root_member = evaluate(call(module, function, "Member"), module)
        principal = human_owner.fixture_principal(root_member.team_id, "alice")
        holder = evaluate(
            call(human_owner, "human", "Member"),
            human_owner,
            world=SimpleNamespace(owner=SimpleNamespace(team_key=root_member.team_key)),
            principal=principal,
            alias="alice",
        )
        certificates = (
            evaluate(
                call(production_authority, "authority", "add_certificate").args[0],
                production_authority,
                member=root_member,
            ),
            evaluate(
                call(human_owner, "human", "add_certificate").args[0], human_owner, member=holder
            ),
        )
        for certificate in certificates:
            verify_team_certificate_signature(certificate, root_member.team_did_key)
        for field in ("alias", "certificate_id"):
            keys = [(c["team_id"], c[field]) for c in certificates]
            if len(set(keys)) != len(keys):
                failures.append(f"{module_name}: duplicate active registration {field}")
        registrations += len(certificates)

    other = human_owner.fixture_principal("other:example.com", "other")
    grant = evaluate(
        call(test_uninstall_cleanup, "another_installation", "_grant"),
        test_uninstall_cleanup,
        other=other,
    )
    admitted = AdmittedInstallation(
        team_id=grant.team_id,
        app_id="secrets",
        installation_id=grant.installation_id,
        generation=grant.generation,
    )
    subject_assignment = next(
        n
        for n in ast.walk(tree(human_owner, "apply_holder"))
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "subject" for t in n.targets)
    )
    subject = evaluate(subject_assignment.value, human_owner, admitted=admitted, principal=other)
    update = next(
        n
        for n in ast.walk(tree(human_owner, "apply_holder"))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "subject"
        and n.func.attr == "update"
    )
    evaluate(
        update, human_owner, subject=subject, credential=credential, contact="other@example.com"
    )

    async def current_key(team_id):
        assert team_id == other.team_id
        return root_member.team_did_key

    verifier = OwnerActVerifier(
        scope=admitted.app_id, audience=origin, acts=HUMAN_ROLE_ACTS, team_key_for=current_key
    )
    owner = TeamOwner(root_member.team_key, verifier, other.team_id)
    signing, signature = evaluate(
        call(human_owner, "apply_holder", "sign"),
        human_owner,
        owner=owner,
        act="human-role.designate",
        subject=subject,
    )
    try:
        _check_owner_act(
            signing,
            signature,
            team_id=other.team_id,
            current_team_key_did=root_member.team_did_key,
            audience=origin,
            acts=HUMAN_ROLE_ACTS,
            now=datetime.now(UTC),
        )
    except Refused as exc:
        failures.append(f"another_installation/apply_holder: {exc}")
    assert not failures, failures
    return {"production_registration_arguments": registrations, "uninstall_subject": "verified"}


def check_legacy_owner_setups(root):
    """Keep intentional raw-role negatives, reject positive owner shortcuts."""
    import ast

    intentional = {
        ("test_human_holders.py", "test_role_reassignment_does_not_heal_an_outstanding_target"),
        (
            "test_human_holders.py",
            "test_lost_holding_before_b3_preparation_is_final_even_during_recovery",
        ),
        ("test_owner_directory.py", "test_the_role_on_another_team_does_not_count"),
        ("test_reinstall.py", "fence"),  # Generic purge data, never owner authority.
    }
    violations = []

    def visit(node, path, function="<module>"):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = node.name
        if isinstance(node, ast.Call):
            name = (
                node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            )
            roles = node.args[2:3] + [k.value for k in node.keywords if k.arg == "role"]
            if name == "assign" and any(
                isinstance(role, ast.Constant)
                and role.value == "secrets.owner"
                or isinstance(role, ast.Name)
                and role.id in {"OWNER", "OWNER_ROLE"}
                for role in roles
            ):
                if (path.name, function) not in intentional:
                    violations.append(f"{path.name}:{function}: owner role flag used as setup")
            if path.name == "test_production_bootstrap.py" and function == (
                "test_a_canonical_component_holder_logs_into_the_production_console"
            ):
                if any(
                    isinstance(n, ast.Dict)
                    and any(
                        isinstance(key, ast.Constant)
                        and key.value == "link_token"
                        and isinstance(value, ast.Name)
                        and value.id == "token"
                        for key, value in zip(n.keys, n.values, strict=True)
                    )
                    for n in ast.walk(node)
                ):
                    violations.append(
                        f"{path.name}:{function}: canonical holder has no legacy token"
                    )
        if path.name == "test_owner_bootstrap.py" and function == "_enrol":
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                violations.append(
                    "test_owner_bootstrap.py:_enrol: obsolete unused owner enrolment helper"
                )
        for child in ast.iter_child_nodes(node):
            visit(child, path, function)

    paths = sorted((root / "naapp/secrets/tests").rglob("*.py"))
    for path in paths:
        visit(ast.parse(path.read_text()), path)
    assert not violations, sorted(set(violations))
    return {"test_files": len(paths), "intentional_raw_role_contexts": len(intentional)}


def main():
    import ast
    import importlib
    import inspect
    import json
    import sys
    from pathlib import Path
    from types import SimpleNamespace

    sys.path.insert(0, str(Path.cwd()))
    sys.path.insert(0, str(Path.cwd() / "e2e"))

    def refuse_socket(event, args):
        if event.startswith("socket."):
            raise RuntimeError("setup sweep attempted socket I/O: " + event)

    sys.addaudithook(refuse_socket)

    root = Path.cwd().parents[1]
    paths = [
        "naapp/secrets/tests/conftest.py",
        "naapp/secrets/tests/console_network.py",
        "naapp/secrets/tests/governance.py",
        "naapp/secrets/tests/human_owner.py",
        "naapp/secrets/tests/owner_history.py",
        "naapp/secrets/tests/test_change_policy.py",
        "naapp/secrets/tests/test_change_sets.py",
        "naapp/secrets/tests/test_console.py",
        "naapp/secrets/tests/test_console_access_browser.py",
        "naapp/secrets/tests/test_console_access_states_browser.py",
        "naapp/secrets/tests/test_console_activity_browser.py",
        "naapp/secrets/tests/test_console_approval_entry_browser.py",
        "naapp/secrets/tests/test_console_audit_delivery_browser.py",
        "naapp/secrets/tests/test_console_bootstrap.py",
        "naapp/secrets/tests/test_console_credential_audit.py",
        "naapp/secrets/tests/test_console_forms.py",
        "naapp/secrets/tests/test_console_jobs_browser.py",
        "naapp/secrets/tests/test_console_reconciliation_browser.py",
        "naapp/secrets/tests/test_console_recovery_browser.py",
        "naapp/secrets/tests/test_console_tokens_browser.py",
        "naapp/secrets/tests/test_console_ui_browser.py",
        "naapp/secrets/tests/test_console_use_approvals_browser.py",
        "naapp/secrets/tests/test_credential_audit.py",
        "naapp/secrets/tests/test_handoff_sessions.py",
        "naapp/secrets/tests/test_human_holders.py",
        "naapp/secrets/tests/test_owner_bootstrap.py",
        "naapp/secrets/tests/test_owner_directory.py",
        "naapp/secrets/tests/test_owner_holding_backfill.py",
        "naapp/secrets/tests/test_passkey_context.py",
        "naapp/secrets/tests/test_passkey_email_cancellation.py",
        "naapp/secrets/tests/test_production_bootstrap.py",
        "naapp/secrets/tests/test_production_hook_network.py",
        "naapp/secrets/tests/test_uninstall_cleanup.py",
        "naapp/secrets/tests/test_use_approvals.py",
    ]
    checks, failures, unknown = [], [], []
    for relative in sorted(set(paths)):
        if (
            not relative.startswith("naapp/secrets/tests/")
            or not relative.endswith(".py")
            or "/fixtures/" in relative
        ):
            continue
        module_name = relative.removeprefix("naapp/secrets/").removesuffix(".py").replace("/", ".")
        module = importlib.import_module(module_name)
        tree = ast.parse((root / relative).read_text())
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            name = call.func.id
            if name not in vars(module) or not inspect.isclass(vars(module)[name]):
                continue
            value = vars(module)[name]
            # Constructors with argument expansion need their actual dynamic values.
            if any(isinstance(a, ast.Starred) for a in call.args) or any(
                k.arg is None for k in call.keywords
            ):
                unknown.append(f"{relative}:{call.lineno}:{name}:expanded arguments")
                continue
            try:
                signature = inspect.signature(value)
            except (TypeError, ValueError):
                continue
            location = f"{relative}:{call.lineno}:{name}"
            try:
                signature.bind(*([None] * len(call.args)), **{k.arg: None for k in call.keywords})
            except TypeError as exc:
                failures.append({"call": location, "error": str(exc)})
            else:
                checks.append(location)
    assert not failures, json.dumps(failures, indent=2)

    from datetime import timedelta

    from aweb_naapp.hooks.owner_act import APP_ACTS
    from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
    from aweb_naapp.hooks.producer import HookProducer, ServerProducer
    from aweb_naapp.roles import is_holding_scope
    from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
    from aweb_naapp.runtime.credential_audit import CredentialAudit
    from aweb_naapp.runtime.installation import InstallationFence
    from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
    from aweb_naapp.runtime.team_auth import AWIDTeamCache
    from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN
    from fastapi import APIRouter, FastAPI
    from nacl.signing import SigningKey
    from pgdbm import AsyncDatabaseManager, DatabaseConfig

    from aweb_secrets.console import OwnerConsole, owner_console_router
    from aweb_secrets.credential_governance import CREDENTIAL_AUDIT_MIGRATIONS, credential_role
    from aweb_secrets.installation_lookup import InstallationLookup
    from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, is_owner_scope
    from aweb_secrets.passkey_context import PasskeyContexts
    from tests.governance import view
    from tests.test_change_sets import Installations
    from tests.test_owner_directory import Audit, Contacts
    from tests.test_production_bootstrap import mounted_owner_console

    # Real constructors only: no connection, registry, transport or verifier calls.
    db = AsyncDatabaseManager(
        DatabaseConfig(
            host="127.0.0.1",
            port=1,
            database="fixture",
            user="fixture",
            password="",
            min_connections=0,
            max_connections=1,
        )
    )
    audit = Audit(db)
    store = PgApprovalStore(db)
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin="https://secrets.example.com", name="Secrets"),
        delivery=Contacts(),
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        holding_scopes=is_holding_scope,
        proof_context=PasskeyContexts(app_id="secrets"),
    )
    fence = InstallationFence(db, app_id="secrets", grants=Installations())
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, service_token=SERVICE_TOKEN)

    async def current_team_key(team_id):
        return (await cache.get(team_id)).team_did_key

    verifier = OwnerActVerifier(
        scope="secrets", audience=passkeys.rp.origin, acts=APP_ACTS, team_key_for=current_team_key
    )
    producer = HookProducer(
        ServerProducer.app(
            origin=passkeys.rp.origin,
            app_id="secrets",
            installation_id="1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
            generation=1,
            kid="test-key",
            seed=bytes(SigningKey.generate()),
        )
    )

    async def registrations(team_id):
        return view()

    recorder = CredentialAudit(
        db=db,
        app_id="secrets",
        fence=fence,
        contexts=passkeys._proof_context,
        owner_act_scope="secrets",
        producer=lambda **scope: producer,
        passkeys=lambda: passkeys,
        role_of=credential_role,
        human_roles=frozenset({OWNER_ROLE}),
        registration_view=registrations,
        max_backlog_age=timedelta(minutes=5),
        migration_module=CREDENTIAL_AUDIT_MIGRATIONS,
    )
    console = OwnerConsole(
        db=db,
        passkeys=passkeys,
        directory=OwnerDirectory(passkeys, db),
        fence=fence,
        verifier=verifier,
        installation=InstallationLookup(fence),
        credential_audit=recorder,
    )
    app = FastAPI()
    router = APIRouter()
    router.include_router(owner_console_router(console))
    app.include_router(router)
    service = SimpleNamespace(console_app=app)
    mounted = mounted_owner_console(service)
    assert mounted is console
    assert mounted.passkeys is passkeys and mounted.credential_audit is recorder
    assert mounted.verifier is verifier and mounted.installation is console.installation
    # The former exact flat lookup must reproduce its StopIteration on this mount.
    try:
        next(
            r
            for r in service.console_app.routes
            if getattr(r, "path", "") == "/installations/{installation_id}/owner-acts"
        )
    except StopIteration:
        pass
    else:
        raise AssertionError("old flat lookup unexpectedly found the lazy included route")

    # Exact helper cache call (not a copied keyword list) must construct successfully.
    call = next(
        n
        for n in ast.walk(ast.parse(Path("tests/human_owner.py").read_text()))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "AWIDTeamCache"
    )
    actual = eval(
        compile(
            ast.fix_missing_locations(ast.Expression(call)), "human_owner.py:AWIDTeamCache", "eval"
        ),
        {
            "AWIDTeamCache": AWIDTeamCache,
            "REGISTRY_URL": REGISTRY_URL,
            "SERVICE_TOKEN": SERVICE_TOKEN,
            "world": SimpleNamespace(registry=SimpleNamespace(transport=None)),
        },
    )
    assert actual.ttl_seconds == 60

    result = {
        "pinned_fastapi": importlib.import_module("fastapi").__version__,
        "constructor_bindings": len(checks),
        "expanded_calls_pending": len(unknown),
        "executed": "real cache, PG manager (unconnected), store, passkeys, fence, verifier, recorder, console, lazy routers; original console identity retained",
        "old_flat_lookup": "StopIteration reproduced",
        "socket_io": False,
        "result": "PASS",
    }
    # Genuine local crypto and HTTPS configuration setup, with no listener/driver.
    import ssl
    import tempfile

    import uvicorn
    from aweb_naapp.hooks.owner_act import HumanCredential
    from aweb_naapp_testing import Member
    from aweb_naapp_testing.network import make_certificates
    from aweb_naapp_testing.owner_acts import TeamOwner
    from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential
    from awid.team_certificate import verify_team_certificate_signature
    from cryptography.hazmat.primitives.asymmetric import ec

    from tests.human_owner import fixture_principal, member_key

    member = Member(
        team_id="backend:acme.com",
        team_key=SigningKey.generate(),
        member_key=member_key("alice"),
        certificate_id="owner-alice",
        alias="alice",
    )
    principal = fixture_principal(member.team_id, "alice")
    member.extra_cert_fields = {"member_did_aw": principal.principal_did}
    certificate = member.certificate()
    assert certificate["member_did_aw"] == principal.principal_did
    # The actual H2 signature verifier runs on the genuine fixture certificate.
    verify_team_certificate_signature(certificate, member.team_did_key)
    device = SoftAuthenticator(passkeys.rp.origin)
    soft = SoftCredential(
        b"fixture-public-id",
        ec.generate_private_key(ec.SECP256R1()),
        passkeys.rp.rp_id,
        b"fixture-public-user",
    )
    device.credentials[soft.credential_id] = soft
    credential = HumanCredential(soft.credential_id, soft.cose_public_key(), soft.rp_id)
    assert credential.rp_id == passkeys.rp.rp_id and credential.sha256
    result["production_fixture_inputs"] = check_production_fixture_inputs(
        credential, passkeys.rp.origin
    )
    result["legacy_owner_fixture_sweep"] = check_legacy_owner_setups(root)
    owner = TeamOwner(member.team_key, verifier, member.team_id, current_team_key)
    signing, signature = owner.sign("app-role.designate", {"role": "fixture"})
    assert signing and signature
    with tempfile.TemporaryDirectory(prefix="cutover-setup-", dir=Path.cwd()) as directory:
        certificates = make_certificates(Path(directory), ["localhost"], ["127.0.0.1"])
        trust = ssl.create_default_context(cafile=str(certificates.ca_file))
        assert trust.cert_store_stats()["x509_ca"] == 1
        config = uvicorn.Config(
            app,
            log_level="error",
            lifespan="off",
            ssl_certfile=str(certificates.cert_file),
            ssl_keyfile=str(certificates.key_file),
        )
        config.load()
        assert config.is_ssl and config.ssl is not None
    print(
        "PASS: real member certificate signature, bound credential, owner signing, private CA and pinned Uvicorn SSL configuration; no socket I/O"
    )

    result["crypto_tls_setup"] = "PASS"
    print(json.dumps({"result": result, "expanded_calls": unknown}, indent=2))


if __name__ == "__main__":
    main()
