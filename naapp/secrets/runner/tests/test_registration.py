"""Registration over a real TLS socket, with locally generated keys and certificate."""

import ipaddress
import json
import os
import pty
import select
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from aweb_secrets_runner.protocol import Refused, decode64, encode64, public_did
from aweb_secrets_runner.registration import register
from aweb_secrets_runner.state import IdentityStore


@pytest.fixture
def service(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "ca.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file = tmp_path / "tls.key"
    key_file.touch(mode=0o600)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    state = {"requests": [], "raw_requests": [], "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            state["raw_requests"].append((self.path, raw, dict(self.headers)))
            state["requests"].append(
                (
                    self.path,
                    json.loads(raw),
                )
            )
            body = state.get("raw", json.dumps(state["response"]).encode())
            status = state["status"]
            headers = state.get("headers", {})
            if respond := state.get("respond"):
                status, body, headers = respond(self.path, raw, dict(self.headers))
            if state.pop("disconnect", False):
                self.close_connection = True
                return
            if event := state.get("received"):
                event.set()
            if resume := state.get("resume"):
                resume.wait(timeout=5)
            self.send_response(status)
            if not state.get("omit_length"):
                self.send_header("Content-Length", str(len(body)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.update(
        origin=f"https://localhost:{server.server_port}",
        ca_file=cert_file,
        code=encode64(os.urandom(32)),
        state_dir=tmp_path / "private",
    )
    state["response"] = {
        "origin": state["origin"],
        "runner_id": "rnr_" + encode64(os.urandom(16)),
        "service_kid": public_did(Ed25519PrivateKey.generate().public_key()),
    }
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def invoke(service):
    return register(**{k: service[k] for k in ("origin", "code", "state_dir", "ca_file")})


def test_registration_sends_only_public_keys_and_pins_response(service):
    identity = invoke(service)
    path, body = service["requests"][0]
    assert path == "/runner/v1/register"
    assert set(body) == {"code", "signing_key", "encryption_key"}
    assert body["code"] == service["code"]
    assert body["signing_key"] == public_did(identity.signing_key.public_key())
    assert (
        decode64(body["encryption_key"]) == identity.encryption_key.public_key().public_bytes_raw()
    )
    assert identity.origin == service["origin"]
    assert identity.runner_id == service["response"]["runner_id"]
    assert identity.service_kid == service["response"]["service_kid"]
    stored = IdentityStore(service["state_dir"]).load()
    assert stored.signing_key.private_bytes_raw() == identity.signing_key.private_bytes_raw()
    assert stored.encryption_key.private_bytes_raw() == identity.encryption_key.private_bytes_raw()
    assert service["state_dir"].stat().st_mode & 0o777 == 0o700
    assert (service["state_dir"] / "identity.json").stat().st_mode & 0o777 == 0o600
    assert service["code"].encode() not in (service["state_dir"] / "identity.json").read_bytes()
    assert encode64(identity.signing_key.private_bytes_raw()) not in repr(identity)
    with pytest.raises(Refused, match="already_registered"):
        invoke(service)
    assert len(service["requests"]) == 1


@pytest.mark.parametrize("defect", ["origin", "runner", "key", "extra", "duplicate", "large"])
def test_invalid_registration_never_pins_or_rotates_local_keys(service, defect):
    if defect == "origin":
        service["response"]["origin"] = "https://other.example"
    elif defect == "runner":
        service["response"]["runner_id"] = "rnr_short"
    elif defect == "key":
        service["response"]["service_kid"] = "did:key:invalid"
    elif defect == "extra":
        service["response"]["extra"] = "refused"
    elif defect == "duplicate":
        service["raw"] = b'{"runner_id":"one","runner_id":"two"}'
    else:
        service["raw"] = b" " * 4097
    with pytest.raises(Refused, match="registration_invalid"):
        invoke(service)
    pending = IdentityStore(service["state_dir"]).load()
    assert pending.runner_id is None and pending.service_kid is None
    old_key = pending.signing_key.private_bytes_raw()
    with pytest.raises(Refused, match="registration_invalid"):
        invoke(service)
    assert IdentityStore(service["state_dir"]).load().signing_key.private_bytes_raw() == old_key


def test_untrusted_tls_and_http_origins_refuse(service):
    args = {k: service[k] for k in ("origin", "code", "state_dir")}
    with pytest.raises(Refused, match="registration_unavailable"):
        register(**args)
    assert service["requests"] == []
    with pytest.raises(Refused, match="registration_invalid"):
        register(**{**args, "origin": args["origin"].replace("https:", "http:")})


def test_refusal_and_redirect_do_not_leak_server_body_or_follow(service):
    for status in (401, 302):
        service["status"] = status
        service["raw"] = os.urandom(24).hex().encode()
        with pytest.raises(Refused) as error:
            invoke(service)
        assert str(error.value) == "registration_refused"
        assert service["raw"].decode() not in repr(error.value)
    assert len(service["requests"]) == 2


def test_registered_key_files_refuse_public_permissions_and_links(service):
    invoke(service)
    path = service["state_dir"] / "identity.json"
    path.chmod(0o644)
    with pytest.raises(Refused, match="state_permissions"):
        IdentityStore(service["state_dir"]).load()
    path.chmod(0o600)
    old = path.with_suffix(".saved")
    path.rename(old)
    path.symlink_to(old)
    with pytest.raises(Refused, match="state_permissions"):
        IdentityStore(service["state_dir"]).load()


def test_an_uncertain_exchange_keeps_keys_and_never_automatically_retries(service):
    service["status"] = 503
    with pytest.raises(Refused, match="registration_unavailable"):
        invoke(service)
    assert len(service["requests"]) == 1
    pending = IdentityStore(service["state_dir"]).load()
    assert pending.runner_id is None
    service["status"] = 200
    registered = invoke(service)
    assert registered.signing_key.private_bytes_raw() == pending.signing_key.private_bytes_raw()
    assert (
        registered.encryption_key.private_bytes_raw() == pending.encryption_key.private_bytes_raw()
    )
    assert service["requests"][0][1] == service["requests"][1][1]


def test_registration_lock_refuses_a_concurrent_exchange_before_network(service):
    store = IdentityStore(service["state_dir"])
    with store.registration_lock():
        with pytest.raises(Refused, match="registration_busy"):
            invoke(service)
    assert service["requests"] == []


def test_real_registration_command_returns_no_private_material(service):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_secrets_runner",
            "register",
            "--origin",
            service["origin"],
            "--state-dir",
            str(service["state_dir"]),
            "--ca-file",
            str(service["ca_file"]),
        ],
        input=(service["code"] + "\n").encode(),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout) == service["response"]
    stored = IdentityStore(service["state_dir"]).load()
    assert (
        encode64(stored.signing_key.private_bytes_raw()).encode()
        not in result.stdout + result.stderr
    )
    assert service["code"].encode() not in result.stdout + result.stderr


def test_registration_command_has_no_code_argument():
    help_result = subprocess.run(
        [sys.executable, "-m", "aweb_secrets_runner", "register", "--help"],
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert b"--code" not in help_result.stdout
    code = encode64(os.urandom(32))
    refused = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_secrets_runner",
            "register",
            "--origin",
            "https://secrets.example",
            "--state-dir",
            "/unused",
            "--code",
            code,
        ],
        capture_output=True,
        check=False,
    )
    assert refused.returncode == 2
    assert code.encode() not in refused.stdout + refused.stderr
    assert refused.stderr == b"runner_arguments_invalid\n"


def test_terminal_prompt_does_not_echo_the_code(service):
    master, slave = pty.openpty()
    command = [
        sys.executable,
        "-m",
        "aweb_secrets_runner",
        "register",
        "--origin",
        service["origin"],
        "--state-dir",
        str(service["state_dir"]),
        "--ca-file",
        str(service["ca_file"]),
    ]
    process = subprocess.Popen(
        command, stdin=slave, stdout=slave, stderr=slave, start_new_session=True
    )
    os.close(slave)
    output = bytearray()
    sent = False
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break  # A closed PTY reports EIO on Linux.
                if not chunk:
                    break
                output.extend(chunk)
                if not sent and b"Registration code: " in output:
                    os.write(master, (service["code"] + "\n").encode())
                    sent = True
            elif process.poll() is not None:
                break
        assert sent, bytes(output)
        assert process.wait(timeout=2) == 0, bytes(output)
        assert service["code"].encode() not in output
        assert service["response"]["runner_id"].encode() in output
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        os.close(master)
