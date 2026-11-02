import subprocess
import sys

from aweb.mcp.server import NormalizeMountedMCPPathMiddleware


def test_import_aweb_package_does_not_import_cli():
    # Probe a cold import without replacing the parent package underneath
    # submodules already imported by the rest of the collected suite.
    subprocess.run([
        sys.executable, "-c",
        "import sys; import aweb; assert aweb.__file__; assert 'aweb.cli' not in sys.modules",
    ], check=True)


def test_import_aweb_api_factory_succeeds():
    subprocess.run([
        sys.executable, "-c",
        "import aweb.api; assert hasattr(aweb.api, 'create_app')",
    ], check=True)


def test_create_app_installs_mcp_path_normalizer_before_startup():
    from aweb.api import create_app

    app = create_app()

    assert any(m.cls is NormalizeMountedMCPPathMiddleware for m in app.user_middleware)
