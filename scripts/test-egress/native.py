#!/usr/bin/env python3
"""Native test guard: deny public HTTP(S), fail even when callers ignore errors.

This is deliberately a soft guard; the Docker runner supplies kernel isolation.
Only the exact nip.io and governance loopback fixtures are forwarded, without DNS.
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


def socket_owner(client_port, proxy_port):
    """The pid holding the client end of a loopback connection to the proxy."""
    if Path('/proc/net/tcp').exists():
        inodes = set()
        for table in ('/proc/net/tcp', '/proc/net/tcp6'):
            for line in Path(table).read_text().splitlines()[1:]:
                fields = line.split()
                local, remote, inode = fields[1], fields[2], fields[9]
                if int(local.rsplit(':', 1)[1], 16) == client_port and int(remote.rsplit(':', 1)[1], 16) == proxy_port:
                    inodes.add(f'socket:[{inode}]')
        for fd in Path('/proc').glob('[0-9]*/fd/*'):
            try:
                if os.readlink(fd) in inodes:
                    return int(fd.parts[2])
            except OSError:
                continue
        return None
    listing = subprocess.run(['lsof', '-nP', '-a', f'-iTCP:{client_port}', '-sTCP:ESTABLISHED', '-Fpn'],
                             capture_output=True, text=True).stdout
    pid = None
    for field in listing.splitlines():
        if field.startswith('p'):
            pid = int(field[1:])
        elif field.startswith('n') and field[1:].startswith(f'127.0.0.1:{client_port}->'):
            return pid
    return None


def process_facts(pid):
    """(parent pid, executable, working directory) of pid. Never its
    arguments: a command line can carry a credential.

    Raises ProcessLookupError once pid has exited: a client can give up and
    exit while the guard is still reading it, between any two reads."""
    if Path('/proc/net/tcp').exists():
        try:
            stat = Path(f'/proc/{pid}/stat').read_text()
            parent = int(stat.rsplit(')', 1)[1].split()[1])
            return parent, os.readlink(f'/proc/{pid}/exe'), os.readlink(f'/proc/{pid}/cwd')
        except FileNotFoundError as error:
            raise ProcessLookupError(pid) from error
    parent, _, executable = subprocess.run(['ps', '-o', 'ppid=,comm=', '-p', str(pid)],
                                           capture_output=True, text=True).stdout.strip().partition(' ')
    if not parent:
        raise ProcessLookupError(pid)
    cwd = subprocess.run(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'],
                         capture_output=True, text=True).stdout
    directory = next((field[1:] for field in cwd.splitlines() if field.startswith('n')), None)
    if directory is None:
        os.kill(pid, 0)  # ProcessLookupError if it exited after ps read it
        directory = 'unavailable'
    return int(parent), executable.strip(), directory


def process_chain(pid, guard_child):
    """pid and its parents up to the guarded command, as far as they can
    still be read."""
    chain = []
    while pid and pid > 1 and len(chain) < 6:
        try:
            parent, executable, cwd = process_facts(pid)
        except ProcessLookupError:
            chain.append(f'pid={pid} exited during attribution')
            break
        chain.append(f'pid={pid} exe={executable} cwd={cwd}')
        if pid == guard_child:
            break
        pid = parent
    return 'client=' + ' <- '.join(chain)


def client_attribution(client_port, proxy_port, guard_child):
    """Which process asked, and its parents up to the guarded command: a Go
    test's t.TempDir working directory names the test, its test binary the
    package."""
    try:
        pid = socket_owner(client_port, proxy_port)
        if pid is None:
            return 'client=unknown (no process holds the connection any more)'
        return process_chain(pid, guard_child)
    except (OSError, ValueError, IndexError) as error:
        return f'client=unknown ({type(error).__name__}: {error})'


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
        if target.hostname not in ('127.0.0.1.nip.io', 'signer.example.com'):
            # Never record credentials, queries or bodies.
            # CONNECT is refused before TLS: HTTPS method attribution is impossible.
            benign = (reserved(target.hostname) or denied_read(target.hostname, self.command)
                      or (self.command == 'CONNECT' and target.port == 443
                          and denied_read(target.hostname, 'GET')))
            receipt = self.server.report if benign else self.server.receipt
            client = '' if benign else ' ' + client_attribution(
                self.client_address[1], self.server.server_port, self.server.child_pid)
            with receipt.open('a') as log:
                log.write(f'{datetime.now(timezone.utc).isoformat()} {self.command} {target.hostname}:{target.port or (443 if target.scheme == "https" else 80)}{client}\n')
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
        server.child_pid = None
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
            # As subprocess.run does, with the child's pid kept so a denial
            # can name the process tree it came from.
            with subprocess.Popen(command, env=env) as child:
                server.child_pid = child.pid
                try:
                    returncode = child.wait()
                except BaseException:
                    child.kill()
                    raise
            result = subprocess.CompletedProcess(command, returncode)
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
