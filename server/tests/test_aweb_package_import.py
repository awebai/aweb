import importlib
import sys

from aweb.mcp.server import NormalizeMountedMCPPathMiddleware


def test_import_aweb_package_does_not_import_cli():
    sys.modules.pop("aweb", None)
    sys.modules.pop("aweb.cli", None)

    module = importlib.import_module("aweb")

    assert module.__file__
    assert "aweb.cli" not in sys.modules


def test_import_aweb_api_factory_succeeds():
    sys.modules.pop("aweb.api", None)

    module = importlib.import_module("aweb.api")

    assert hasattr(module, "create_app")


def test_create_app_installs_mcp_path_normalizer_before_startup():
    from aweb.api import create_app

    app = create_app()

    assert any(m.cls is NormalizeMountedMCPPathMiddleware for m in app.user_middleware)
