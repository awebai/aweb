"""Real local DNS and TLS servers for network tests through the egress guard.

The DNS server answers A and AAAA queries from a table the test controls and
counts every query, so a test can change an answer between two lookups. The
TLS server presents a certificate from a throwaway CA, records the SNI name,
request line and headers of every request, and serves a few fixed paths.
"""

from __future__ import annotations

import asyncio
import datetime
import gzip
import ipaddress
import json
import socket
import ssl
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

Answer = list[str] | Callable[[int], list[str]]


def local_address() -> str:
    """This host's own non-loopback IPv4 address.

    The guard refuses loopback for every destination, internal ones included,
    so the TLS server listens on one of the host's own addresses: the one its
    outbound route uses, or, on a network with no route out (the gate's
    isolated runner), one its own name resolves to locally. Connecting a UDP
    socket sends nothing; it only picks the route.
    """
    for address in _route_address(), *_named_addresses():
        if address is not None and not ipaddress.ip_address(address).is_loopback:
            return address
    raise RuntimeError("the egress network tests need a non-loopback IPv4 address on this host")


def _route_address() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return str(probe.getsockname()[0])
    except OSError:
        return None
    finally:
        probe.close()


def _named_addresses() -> list[str]:
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return []
    return [str(info[4][0]) for info in infos]


@dataclass
class DnsServer:
    """Answers ``records[(name, "A"|"AAAA")]``; a callable gets the query count."""

    records: dict[tuple[str, str], Answer] = field(default_factory=dict)
    queries: Counter[tuple[str, str]] = field(default_factory=Counter)
    # Seconds to wait before each answer, as a slow resolver would.
    delay: float = 0.0
    port: int = 0
    _transport: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        server = self

        class Protocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                answer = server._answer(data)
                send = self.transport.sendto  # type: ignore[attr-defined]
                if server.delay:
                    loop.call_later(server.delay, send, answer, addr)
                else:
                    send(answer, addr)

        transport, _ = await loop.create_datagram_endpoint(Protocol, local_addr=("127.0.0.1", 0))
        self._transport = transport  # type: ignore[assignment]
        self.port = transport.get_extra_info("sockname")[1]

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    def _answer(self, wire: bytes) -> bytes:
        query = dns.message.from_wire(wire)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        kind = dns.rdatatype.to_text(question.rdtype)
        self.queries[(name, kind)] += 1
        if not any(key[0] == name for key in self.records):
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()
        answer = self.records.get((name, kind), [])
        values = answer(self.queries[(name, kind)]) if callable(answer) else answer
        if values:
            response.answer.append(
                dns.rrset.from_text_list(question.name, 60, dns.rdataclass.IN, kind, values)
            )
        return response.to_wire()


@dataclass(frozen=True)
class Certificates:
    ca_file: Path
    cert_file: Path
    key_file: Path


def make_certificates(directory: Path, names: list[str], addresses: list[str]) -> Certificates:
    """A throwaway CA and a server certificate for ``names`` and ``addresses``."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "egress test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    alt_names: list[x509.GeneralName] = [x509.DNSName(name) for name in names]
    alt_names += [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    paths = Certificates(directory / "ca.pem", directory / "server.pem", directory / "server.key")
    paths.ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths.cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths.key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return paths


@dataclass
class Seen:
    sni: str | None
    request_line: str
    headers: list[tuple[str, str]]
    body: bytes


@dataclass
class TlsServer:
    """An HTTPS/1.1 server on ``host`` with a few fixed paths.

    ``/ok`` answers JSON, ``/redirect`` answers 302 to another host,
    ``/big?n=`` answers ``n`` bytes, ``/slow`` never answers, ``/encoded``
    answers a gzip-encoded body, and ``/echo`` returns the request it saw as
    JSON.
    """

    certificates: Certificates
    host: str
    seen: list[Seen] = field(default_factory=list)
    port: int = 0
    _server: asyncio.Server | None = None

    async def start(self) -> None:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certificates.cert_file, self.certificates.key_file)
        sni: dict[int, str | None] = {}

        def remember(sock: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> None:
            sni[id(sock)] = name

        context.sni_callback = remember  # type: ignore[assignment]

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await self._handle(reader, writer, sni.get(id(writer.get_extra_info("ssl_object"))))
            except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
                pass
            finally:
                writer.close()

        self._server = await asyncio.start_server(handle, self.host, 0, ssl=context)
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, sni: str | None
    ) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = [tuple(line.split(": ", 1)) for line in lines[1:] if line]
        length = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
        body = await reader.readexactly(length) if length else b""
        seen = Seen(sni, lines[0], [(k, v) for k, v in headers], body)
        self.seen.append(seen)
        path = lines[0].split(" ")[1]
        if path == "/slow":
            await asyncio.sleep(3600)
        if path == "/redirect":
            await _respond(writer, 302, b"", [("Location", "https://elsewhere.example/next")])
        elif path.startswith("/big?n="):
            await _respond(writer, 200, b"x" * int(path.split("=")[1]), [])
        elif path == "/encoded":
            await _respond(writer, 200, gzip.compress(b"hidden"), [("Content-Encoding", "gzip")])
        elif path == "/echo":
            echoed = {"request_line": seen.request_line, "headers": seen.headers, "sni": sni}
            await _respond(writer, 200, json.dumps(echoed).encode(), [])
        else:
            await _respond(writer, 200, b'{"ok": true}', [("Content-Type", "application/json")])


async def _respond(
    writer: asyncio.StreamWriter, status: int, body: bytes, headers: list[tuple[str, str]]
) -> None:
    head = [f"HTTP/1.1 {status} X", f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{name}: {value}" for name, value in headers]
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)
    await writer.drain()
