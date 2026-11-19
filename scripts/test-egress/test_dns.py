"""Direct packet controls for the no-upstream DNS sink; no sockets or services."""

from pathlib import Path
import struct
import tempfile
import unittest

from dns import response


def question(host, kind=1, klass=1):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in host.split(".")
    )
    return (
        struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\0"
        + struct.pack("!HH", kind, klass)
    )


class DNSPackets(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.receipt = Path(directory.name) / "dns-denied.log"

    def query(self, host, kind=1, klass=1):
        packet = question(host, kind, klass)
        reply = response(packet, self.receipt)
        self.assertEqual(reply[:2], packet[:2])
        self.assertEqual(reply[12 : len(packet)], packet[12:])
        return struct.unpack("!HHHHH", reply[2:12]), reply[len(packet) :]

    def assert_unreported(self):
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.receipt.with_suffix(".log.reported").exists())

    def test_governance_alias_answers_only_ipv4_loopback(self):
        for host in ("signer.example.com", "SIGNER.EXAMPLE.COM"):
            with self.subTest(host=host):
                header, answer = self.query(host)
                self.assertEqual(header, (0x8180, 1, 1, 0, 0))
                self.assertEqual(
                    answer,
                    b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + b"\x7f\0\0\1",
                )
        self.assert_unreported()

    def test_governance_alias_has_no_other_records(self):
        # Keep the sink's existing empty-answer behavior for other record types
        # and classes; the runner's declared fixture is IPv4 loopback only.
        for kind, klass in ((28, 1), (65, 1), (15, 1), (255, 1), (1, 3)):
            with self.subTest(kind=kind, klass=klass):
                header, answer = self.query("signer.example.com", kind, klass)
                self.assertEqual(header, (0x8180, 1, 0, 0, 0))
                self.assertEqual(answer, b"")
        self.assert_unreported()

    def test_existing_loopback_answers_are_unchanged(self):
        for host, kind, address in (
            ("localhost", 1, b"\x7f\0\0\1"),
            ("localhost", 28, b"\0" * 15 + b"\1"),
            ("127.0.0.1.nip.io", 1, b"\x7f\0\0\1"),
            ("127.0.0.1.nip.io", 28, b""),
        ):
            with self.subTest(host=host, kind=kind):
                header, answer = self.query(host, kind)
                self.assertEqual(header, (0x8180, 1, int(bool(address)), 0, 0))
                if address:
                    self.assertEqual(
                        answer,
                        b"\xc0\x0c"
                        + struct.pack("!HHIH", kind, 1, 0, len(address))
                        + address,
                    )
                else:
                    self.assertEqual(answer, b"")
        self.assert_unreported()

    def test_other_names_still_fail_the_guard_for_all_record_types(self):
        expected = []
        for host in (
            "other.example.com",
            "sub.signer.example.com",
            "signer.example.com.attacker.com",
            "signerx.example.com",
            "example.com",
        ):
            for kind in (1, 28, 65):
                with self.subTest(host=host, kind=kind):
                    header, answer = self.query(host, kind)
                    self.assertEqual(header, (0x8183, 1, 0, 0, 0))
                    self.assertEqual(answer, b"")
                    expected.append(host)
                    self.assertEqual(self.receipt.read_text().splitlines(), expected)

    def test_reserved_name_keeps_its_separate_report(self):
        header, answer = self.query("unpublished.test")
        self.assertEqual(header, (0x8183, 1, 0, 0, 0))
        self.assertEqual(answer, b"")
        self.assertFalse(self.receipt.exists())
        self.assertEqual(
            self.receipt.with_suffix(".log.reported").read_text(), "unpublished.test\n"
        )


if __name__ == "__main__":
    unittest.main()
