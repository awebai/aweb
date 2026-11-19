"""A disposable stack CA issues a server certificate for any DNS name a stack uses."""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

from aweb_naapp_testing.network import make_certificates

# A stack's scoped service name: a 63-character label under .test, longer than
# the 64 characters a certificate's common name may hold.
SCOPED_NAME = "aweb-e2e-stack-3473101995-libr-7fe3560b64f34f6c18de1ee54f8b7398.test"


def test_a_client_verifies_a_scoped_stack_name_longer_than_a_common_name(tmp_path: Path) -> None:
    assert len(SCOPED_NAME) > 64
    certificates = make_certificates(tmp_path, [SCOPED_NAME], ["127.0.0.1"])
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(certificates.cert_file, certificates.key_file)
    client_context = ssl.create_default_context(cafile=str(certificates.ca_file))

    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def serve_one() -> None:
            connection, _ = listener.accept()
            with server_context.wrap_socket(connection, server_side=True):
                pass

        server = threading.Thread(target=serve_one)
        server.start()
        with (
            socket.create_connection(("127.0.0.1", port)) as raw,
            client_context.wrap_socket(raw, server_hostname=SCOPED_NAME) as tls,
        ):
            assert tls.version() is not None
        server.join(timeout=5)
