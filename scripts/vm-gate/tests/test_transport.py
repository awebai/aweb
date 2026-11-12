from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from vm_gate.transport import Transport
from vm_gate.errors import Infrastructure


class TransportTests(unittest.TestCase):
    def keys(self, directory):
        for name in ["ssh-host-key", "ssh-key"]:
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(Path(directory) / name),
                ],
                check=True,
                capture_output=True,
            )

    def test_first_contact_is_pinned_and_a_changed_expected_key_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            self.keys(directory)
            t = Transport(Path(directory), "192.0.2.1", 11)
            self.assertIn("StrictHostKeyChecking=yes", t.options)
            expected = (Path(directory) / "ssh-host-key.pub").read_text().split()[:2]
            row = (Path(directory) / "known_hosts").read_text().split()
            self.assertEqual(row[:3], ["aweb-vm-gate-server-11", *expected])
            wrong = (Path(directory) / "ssh-key.pub").read_text().split()[:2]
            (Path(directory) / "known_hosts").write_text(
                "aweb-vm-gate-server-11 " + " ".join(wrong) + "\n"
            )
            with self.assertRaisesRegex(Infrastructure, "host key pin differs"):
                Transport(Path(directory), "192.0.2.1", 11)

    def test_mismatch_control_requires_host_verification_error_not_a_network_error(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            self.keys(directory)
            transport = Transport(Path(directory), "192.0.2.1", 11)
            for status, stderr, accepted in [
                (0, "", False),
                (255, "Connection refused", False),
                (255, "Host key verification failed.", True),
            ]:
                with self.subTest(status=status, stderr=stderr):
                    result = SimpleNamespace(
                        returncode=status, stdout="", stderr=stderr
                    )
                    with patch.object(transport, "invoke", return_value=result):
                        if accepted:
                            self.assertIs(transport.prove_mismatch(timeout=1), result)
                        else:
                            with self.assertRaisesRegex(
                                Infrastructure, "required refusal"
                            ):
                                transport.prove_mismatch(timeout=1)
            wrong = (Path(directory) / "known_hosts-mismatch").read_text().split()[1:3]
            self.assertNotEqual(
                wrong, (Path(directory) / "ssh-host-key.pub").read_text().split()[:2]
            )

    def test_alias_is_per_server_and_child_does_not_inherit_token(self):
        with tempfile.TemporaryDirectory() as directory:
            self.keys(directory)
            t = Transport(Path(directory), "192.0.2.1", 11)
            with (
                patch.dict(
                    "os.environ", {"HCLOUD_TOKEN": "fixture-secret"}, clear=True
                ),
                patch(
                    "subprocess.run",
                    return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
                ) as run,
            ):
                t.run("true", timeout=10)
            args = run.call_args.args[0]
            kwargs = run.call_args.kwargs
            self.assertIn("HostKeyAlias=aweb-vm-gate-server-11", args)
            self.assertNotIn("HCLOUD_TOKEN", kwargs["env"])
            other = Transport(Path(directory), "192.0.2.1", 12)
            self.assertNotEqual(t.options, other.options)

    def test_transfer_is_an_argument_vector_with_same_identity_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            self.keys(directory)
            t = Transport(Path(directory), "192.0.2.1", 11)
            with patch(
                "subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
            ) as run:
                t.copy(
                    Path(directory) / "with spaces", "/opt/vm-gate/input", timeout=10
                )
            args = run.call_args.args[0]
            self.assertEqual(args[-2], str(Path(directory) / "with spaces"))
            self.assertIn("HostKeyAlias=aweb-vm-gate-server-11", args)


if __name__ == "__main__":
    unittest.main()
