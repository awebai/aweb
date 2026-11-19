"""Setup evidence for logs' reader tests, with socket I/O forbidden: every call
the reader test modules make to a class or function they name binds to its
signature, and the app composes as production does up to its lifespan.

Run from naapp/logs: uv run --no-sync python tests/check_reader_setup.py
This is not a native test: no database, registry or server is reached, and the
lifespan, where the reader services are composed, does not run.
"""


def main() -> None:
    import importlib
    import sys
    import tempfile
    from pathlib import Path

    sys.path.insert(0, str(Path.cwd()))

    from aweb_naapp_testing.setup_check import bind_calls, forbid_sockets

    forbid_sockets()
    modules = [
        "tests.reader_world",
        "tests.test_app",
        "tests.test_manifest",
        "tests.test_reader_handoffs",
        "tests.test_reader_holdings",
        "tests.test_reader_removal",
        "tests.test_reader_service",
        "tests.test_reader_viewer",
        "tests.test_reader_viewer_browser",
    ]
    for name in modules:
        print(f"{name}: {bind_calls(importlib.import_module(name))} calls bind")

    from aweb_logs.app import create_app
    from aweb_logs.config import LogsSettings
    from tests.deployment import TEST_APP_ID, no_mail, write_key_files

    with tempfile.TemporaryDirectory() as directory:
        settings = LogsSettings(
            _env_file=None,
            database_url="postgresql://unconnected/logs",
            purge_ledger_database_url="postgresql://unconnected/logs_purges",
            public_origin="https://logs.example.test",
            console_origin="https://console.logs.example.test",
            app_id=TEST_APP_ID,
            app_key_files=write_key_files(Path(directory)),
        )
        service = create_app(settings, email=no_mail())
        owner_acts = service.api_app.state.runtime.manifest.owner_acts
        assert owner_acts["origin"] == settings.console_origin
    print("create_app composes, publishing owner_acts on the console origin")


if __name__ == "__main__":
    main()
