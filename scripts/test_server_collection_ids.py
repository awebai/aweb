"""Fresh processes must collect the same IDs from the real parametrizations."""

import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "test_app_hook_resolution.py": "test_own_bindings_need_exactly_one_well_formed_selector",
    "test_mail_thread_embedding.py": "test_exact_peer_check_validates_native_locators",
    "test_team_room.py": "test_room_refuses_wrong_signed_bindings",
    "test_mcp_mail_chat.py": "test_mcp_auth_rejects_invalid_proxy_team_id",
}


class CollectionIds(unittest.TestCase):
    def test_real_decorators_collect_identically_in_fresh_processes(self):
        # Execute actual parameter expressions and pytest collection, with inert
        # bodies and no product/service imports. This is collection evidence only.
        source = "import pytest\nfrom uuid import uuid4\nfrom datetime import datetime,timezone,timedelta\nHOOK_PATH='aweb.hooks/fixture/v1'\nPEER='did:aw:fixture'\n"
        for name, function in CASES.items():
            tree = ast.parse((ROOT / "server/tests" / name).read_text())
            node = next(
                n
                for n in tree.body
                if isinstance(n, ast.AsyncFunctionDef) and n.name == function
            )
            node.decorator_list = [
                dec for dec in node.decorator_list if "parametrize" in ast.unparse(dec)
            ]
            node.body = [ast.Pass()]
            node.returns = None
            for arg in node.args.args:
                arg.annotation = None
            source += ast.unparse(ast.fix_missing_locations(node)) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test = root / "test_collection.py"
            test.write_text(source)
            collected = []
            for _ in range(2):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-m",
                        "pytest",
                        "--collect-only",
                        "--noconftest",
                        "-q",
                        str(test),
                    ],
                    cwd=root,
                    env={
                        "PATH": os.defpath,
                        "HOME": tmp,
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    },
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                ids = [
                    line
                    for line in result.stdout.splitlines()
                    if line.startswith("test_collection.py::")
                ]
                self.assertEqual(len(ids), 24)
                collected.append(ids)
            self.assertEqual(collected[0], collected[1])


if __name__ == "__main__":
    unittest.main()
