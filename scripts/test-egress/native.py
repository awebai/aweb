#!/usr/bin/env python3
"""Native test guard: deny public HTTP(S), fail even when callers ignore errors.

This is deliberately a soft guard; the Docker runner supplies kernel isolation.
Only the existing exact nip.io loopback fixture is forwarded, without DNS.
"""
import argparse
from datetime import datetime, timezone
import http.client
import http.server
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from policy import reserved, denied_read


class GuardServer(http.server.ThreadingHTTPServer):
    daemon_threads = False

    def handle_error(self, request, client_address):
        self.failed = True
        super().handle_error(request, client_address)


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def handle_request(self):
        target = urlsplit(('https://' if self.command == 'CONNECT' else '') + self.path)
        if target.hostname != '127.0.0.1.nip.io':
            # Never record credentials, queries or bodies.
            # CONNECT is refused before TLS: HTTPS method attribution is impossible.
            benign = (reserved(target.hostname) or denied_read(target.hostname, self.command)
                      or (self.command == 'CONNECT' and target.port == 443
                          and denied_read(target.hostname, 'GET')))
            receipt = self.server.report if benign else self.server.receipt
            with receipt.open('a') as log:
                log.write(f'{datetime.now(timezone.utc).isoformat()} {self.command} {target.hostname}:{target.port or (443 if target.scheme == "https" else 80)}\n')
                log.flush()
            self.send_error(403, 'test egress denied')
            return
        port = target.port or (443 if target.scheme == 'https' else 80)
        if self.command == 'CONNECT':
            with socket.create_connection(('127.0.0.1', port), timeout=10) as upstream:
                self.send_response(200)
                self.end_headers()
                peers = [self.connection, upstream]
                while True:
                    ready, _, _ = select.select(peers, [], [], 30)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.connection else self.connection).sendall(data)
        else:
            upstream = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                headers = {k: v for k, v in self.headers.items() if k.lower() not in ('proxy-connection', 'connection')}
                upstream.request(self.command, target.path + ('?' + target.query if target.query else ''), body, headers)
                response = upstream.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                upstream.close()

    do_CONNECT = do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command is required after --')
    with tempfile.TemporaryDirectory(prefix='aw-test-proxy-') as tmp:
        receipt = args.log or Path(tmp) / 'denied.log'
        # Refuse to overwrite a previous evidence receipt.
        receipt.open('x').close()
        server = GuardServer(('127.0.0.1', 0), Proxy)
        server.failed = False
        server.receipt = receipt
        server.report = receipt.with_suffix(receipt.suffix + ".reported")
        server.report.open("x").close()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy = f'http://127.0.0.1:{server.server_port}'
        env = dict(os.environ)
        for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
            env[name] = env[name.lower()] = proxy
        env['NO_PROXY'] = env['no_proxy'] = 'localhost,127.0.0.1,::1,.test,.example,.invalid,.localhost'
        try:
            result = subprocess.run(command, env=env, check=False)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        reported = server.report.read_text()
        if reported:
            print("TEST EGRESS REFUSED (reserved/allowlisted):\n" + reported, flush=True)
        denied = receipt.read_text()
        if server.failed:
            print("TEST EGRESS GUARD ERROR", flush=True)
            return 1
        if denied:
            print('TEST EGRESS DENIED (fails independently of child status):\n' + denied, flush=True)
            return 1
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
