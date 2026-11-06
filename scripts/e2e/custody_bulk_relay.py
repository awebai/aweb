"""Latency controls around real HTTP/custody; never substitute an API result."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import socketserver
import threading
import time

ROOT = Path('/work')
LOCK = threading.Lock()


def settings():
    return json.loads((ROOT / 'control.json').read_text())


def record(value):
    with LOCK:
        with (ROOT / 'requests.jsonl').open('a') as out:
            out.write(json.dumps(value) + '\n')


def forward(handler, target, line, headers, body, *, unix=False):
    mode = settings()
    method, path, _ = line.decode().strip().split(' ', 2)
    page = path.startswith('/v1/messages/conversations/')
    stored = path.startswith('/v1/messages/') and not page and path.count('/') == 3
    freshness = path.startswith('/v1/identity-grants/') and path.endswith('/status')
    observation = dict(case=mode['case'], path=path, method=method, started=time.monotonic())
    # Record an attempt even if the caller cancels before the response.
    record(dict(observation, phase='started'))
    connection = http.client.HTTPConnection('server' if not unix else 'local', 8000, timeout=30)
    if unix:
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(30)
        connection.sock.connect(target)
    try:
        if page and mode.get('page_close'):
            return  # Actual connection close: exercise the bounded transport retry policy.
        delay = (mode.get('rpc_delay', 0) if unix and path == '/unwrap_e2ee_message' else
                 mode.get('page_delay', 0) if page else
                 mode.get('stored_delay', 0) if stored else
                 mode.get('freshness_delay', 0) if freshness else 0)
        if delay:
            time.sleep(delay)
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        data = response.read()
        handler.wfile.write(f'HTTP/1.1 {response.status} {response.reason}\r\n'.encode())
        for key, value in response.getheaders():
            if key.lower() not in ('content-length', 'connection', 'transfer-encoding'):
                handler.wfile.write(f'{key}: {value}\r\n'.encode())
        handler.wfile.write(f'Content-Length: {len(data)}\r\nConnection: close\r\n\r\n'.encode())
        handler.wfile.flush()
        if page and mode.get('body_delay'):
            # Headers really reach the client before the response body stalls.
            record(dict(observation, phase='headers', status=response.status))
            time.sleep(mode['body_delay'])
        handler.wfile.write(data)
        observation['status'] = response.status
    except (OSError, http.client.HTTPException) as error:
        observation['error'] = type(error).__name__
    finally:
        connection.close()
        record(dict(observation, phase='finished', seconds=time.monotonic() - observation['started']))


class Front(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        forward(self, None, self.raw_requestline, dict(self.headers), body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_request


class UnixRelay(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, target):
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line, headers = self.rfile.readline(), {}
                while header := self.rfile.readline():
                    if header in (b'\r\n', b'\n'):
                        break
                    key, value = header.decode().split(':', 1)
                    headers[key] = value.strip()
                body = self.rfile.read(int(headers.get('Content-Length', '0')))
                forward(self, target, line, headers, body, unix=True)
        super().__init__(path, Handler)


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8000), Front).serve_forever()
