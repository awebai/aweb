"""Execute the new fixtures' local constructor paths with socket I/O forbidden.

Run from naapp-lib: uv run --no-sync python tests/check_owner_act_router_setup.py
This is setup evidence, not a native test: registry/server/DB constructors remain
unconnected, and authority, migration, transaction and HTTP bodies never run.
"""


def main():
    import ast
    import copy
    import importlib
    import inspect
    import json
    import sys
    import tempfile
    from pathlib import Path

    # Executing a script under tests must not let tests/email shadow stdlib email.
    sys.path = [path for path in sys.path if Path(path).resolve() != Path(__file__).parent]
    sys.path.insert(0, str(Path.cwd()))

    def refuse_socket(event, args):
        if event.startswith("socket."):
            raise RuntimeError("setup checker attempted socket I/O: " + event)

    sys.addaudithook(refuse_socket)

    from datetime import UTC, datetime
    from uuid import uuid4

    from aweb.db import DatabaseInfra
    from aweb.testing import Server
    from aweb_naapp_testing import Member
    from aweb_naapp_testing.server import Coordination
    from awid.registry import RegistryClient
    from awid.team_certificate import verify_team_certificate_signature
    from awid_service.testing import REGISTRY_URL, Registry, ServiceTransport
    from fastapi import FastAPI
    from pgdbm import AsyncDatabaseManager, DatabaseConfig
    from pydantic import ValidationError

    from aweb_naapp.hooks.owner_act import HumanCredential, _check_owner_act
    from aweb_naapp.runtime.owner_act_delivery import OwnerActDelivery, OwnerActEffectResult
    from tests.runtime.approvals.test_human_role_holders import PRINCIPAL

    publication = importlib.import_module("tests.runtime.test_manifest_publication_v3")
    route_tests = importlib.import_module("tests.runtime.test_owner_act_router")
    modules = (publication, route_tests)
    bindings = 0
    for module in modules:
        for node in ast.walk(ast.parse(Path(module.__file__).read_text())):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            value = vars(module).get(node.func.id)
            if not inspect.isclass(value):
                continue
            assert not any(isinstance(arg, ast.Starred) for arg in node.args)
            assert all(kw.arg is not None for kw in node.keywords)
            try:
                signature = inspect.signature(value)
            except (TypeError, ValueError):
                # C builtins such as timedelta have no inspectable signature;
                # the fixture's actual local construction below still runs them.
                continue
            signature.bind(*([None] * len(node.args)), **{kw.arg: None for kw in node.keywords})
            bindings += 1

    db = AsyncDatabaseManager(
        DatabaseConfig(
            connection_string="postgresql://fixture@127.0.0.1:1/fixture",
            schema="naapp_test",
            min_connections=0,
            max_connections=2,
        )
    )
    registry_app = FastAPI()
    registry = Registry(registry_app, db, ServiceTransport(registry_app))
    server_app = FastAPI()
    server = Server(server_app, DatabaseInfra(), ServiceTransport(server_app))
    coordination = Coordination(registry, server)
    member = Member(team_id=route_tests.TEAM)
    member.extra_cert_fields = {"member_did_aw": PRINCIPAL}
    identity_client = RegistryClient(REGISTRY_URL, transport=registry.transport)
    human = (member, PRINCIPAL, identity_client, None, None)
    installation = {"installation_id": str(uuid4()), "generation": 1}

    with tempfile.TemporaryDirectory(prefix="owner-act-setup-") as directory:
        root = Path(directory)
        publication_dir = root / "publication"
        publication_dir.mkdir()
        published = publication.runtime(publication_dir)
        assert published.manifest.manifest_version == 3
        assert published.manifest_variant_bytes(2)

        fixture = next(
            node
            for node in ast.parse(Path(route_tests.__file__).read_text()).body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "world"
        )
        route_dir = root / "router"
        route_dir.mkdir()
        context = {
            **vars(route_tests),
            "tmp_path": route_dir,
            "coordination": coordination,
            "human": human,
            "db": db,
            "installation": installation,
        }
        settings_call = next(
            node
            for node in ast.walk(fixture)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ExampleSettings"
        )

        # Execute the exact synchronous statements from the fixture, including
        # settings/runtime/router constructors. Skip only awaited/native work.
        for statement in fixture.body:
            if isinstance(statement, ast.AsyncWith):
                continue
            if any(isinstance(node, (ast.Await, ast.Yield)) for node in ast.walk(statement)):
                # Function definitions contain awaited work but do not execute it.
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
            module = ast.fix_missing_locations(ast.Module(body=[statement], type_ignores=[]))
            exec(compile(module, route_tests.__file__, "exec"), context)
        result_call = next(node.value for node in ast.walk(fixture) if isinstance(node, ast.Yield))
        world = eval(
            compile(
                ast.fix_missing_locations(ast.Expression(result_call)), route_tests.__file__, "eval"
            ),
            context,
        )
        assert world.runtime is context["runtime"] and world.effect is context["effect"]
        assert world.runtime.settings.db_schema == db.config.schema_name

        # Show that the old field access really fails against these dependencies.
        broken = copy.deepcopy(settings_call)
        keyword = next(kw for kw in broken.keywords if kw.arg == "db_schema")
        keyword.value = ast.parse("db.config.schema", mode="eval").body
        try:
            eval(
                compile(
                    ast.fix_missing_locations(ast.Expression(broken)), "old-schema-field", "eval"
                ),
                context,
            )
        except ValidationError as exc:
            assert any(error["loc"] == ("db_schema",) for error in exc.errors())
        else:
            raise AssertionError("old fixture schema field did not reproduce validation failure")

        body = world.body()
        import base64

        signing = base64.b64decode(body["signing"])
        checked = _check_owner_act(
            signing,
            body["signature"],
            team_id=member.team_id,
            current_team_key_did=member.team_did_key,
            audience=route_tests.ORIGIN,
            acts=route_tests.HUMAN_ROLE_ACTS,
            now=datetime.now(UTC),
        )
        certificate = json.dumps(member.certificate()).encode()
        verify_team_certificate_signature(member.certificate(), member.team_did_key)
        delivery = OwnerActDelivery(
            signing,
            body["signature"],
            checked.act,
            checked.team_id,
            checked.subject,
            HumanCredential.parse(body["credential"]),
            body["notice_contact"],
            certificate,
        )
        route_tests.SqlPreparedEffect(world.effect, delivery, None, checked.subject)
        OwnerActEffectResult(checked.act, route_tests.ROLE, PRINCIPAL, datetime.now(UTC))

    print(
        json.dumps(
            {
                "constructor_bindings": bindings,
                "fixture_constructor_paths": 2,
                "old_schema_failure_reproduced": True,
                "local_certificate_and_act_signatures": "PASS",
                "socket_io": False,
                "native_bodies": "NOT RUN",
                "result": "PASS",
            }
        )
    )


if __name__ == "__main__":
    main()
