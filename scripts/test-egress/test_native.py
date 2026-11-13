"""Real subprocess controls: no mocked transport or service responses."""
from contextlib import contextmanager
import http.server
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

RUNNER = Path(__file__).with_name('native.py')


@contextmanager
def local_fixture():
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers['Host']))
            body = b'local fixture'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_port, seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class NativeGuard(unittest.TestCase):
    def run_request(self, url, method='GET'):
        code = ('import urllib.request\n'
                f'req = urllib.request.Request({url!r}, method={method!r})\n'
                'try:\n urllib.request.urlopen(req, timeout=2)\n'
                'except OSError:\n pass\n')
        return subprocess.run([sys.executable, str(RUNNER), '--', sys.executable, '-c', code], capture_output=True, text=True)

    def test_governance_alias_http_reaches_only_loopback_and_keeps_host(self):
        with local_fixture() as (port, seen):
            code = (
                'import urllib.request\n'
                f'with urllib.request.urlopen("http://signer.example.com:{port}/fixture", timeout=2) as response:\n'
                ' assert response.status == 200\n'
                ' assert response.read() == b"local fixture"\n'
            )
            result = subprocess.run(
                [sys.executable, str(RUNNER), '--', sys.executable, '-c', code],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(seen, [('/fixture', f'signer.example.com:{port}')])
            self.assertNotIn('TEST EGRESS', result.stdout)

    def test_governance_alias_connect_tunnels_to_loopback_without_resolving_alias(self):
        with local_fixture() as (port, seen):
            # CONNECT is transparent: exercise its bytes over a real tunnel,
            # independently of browser DNS and TLS fixture dependencies.
            code = (
                'import http.client, os\n'
                'from urllib.parse import urlsplit\n'
                'proxy = urlsplit(os.environ["HTTPS_PROXY"])\n'
                'connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=2)\n'
                f'connection.set_tunnel("signer.example.com", {port})\n'
                'connection.request("GET", "/tunnel")\n'
                'response = connection.getresponse()\n'
                'assert response.status == 200\n'
                'assert response.read() == b"local fixture"\n'
                'connection.close()\n'
            )
            result = subprocess.run(
                [sys.executable, str(RUNNER), '--', sys.executable, '-c', code],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(seen, [('/tunnel', f'signer.example.com:{port}')])
            self.assertNotIn('TEST EGRESS', result.stdout)

    def test_governance_alias_neighbours_remain_denied_and_never_reach_fixture(self):
        with local_fixture() as (port, seen):
            for host in ('other.example.com', 'signer.example.com.attacker.com'):
                with self.subTest(host=host):
                    result = self.run_request(f'http://{host}:{port}/fixture')
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f'GET {host}:{port}', result.stdout)
            self.assertEqual(seen, [])

    def test_swallowed_production_write_fails(self):
        result = self.run_request('https://api.awid.ai/v1/did/test/encryption-key', 'POST')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('CONNECT api.awid.ai:443', result.stdout)

    def test_reserved_refused_without_violation(self):
        result = self.run_request('https://app.example/discovery')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('TEST EGRESS DENIED', result.stdout)

    def test_hosted_production_https_is_refused_and_fails(self):
        result = self.run_request('https://app.aweb.ai/anything', 'POST')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('CONNECT app.aweb.ai:443', result.stdout)

        self.assertIn('TEST EGRESS DENIED', result.stdout)

    def test_hosted_production_plain_http_write_fails(self):
        result = self.run_request('http://app.aweb.ai/anything', 'POST')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('POST app.aweb.ai:80', result.stdout)

    def test_compiled_child_ignoring_error_still_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'main.go'
            source.write_text('package main\nimport "net/http"\nfunc main(){ http.Post("https://api.awid.ai/v1/did/test/encryption-key", "application/json", nil) }\n')
            binary = Path(tmp) / 'child'
            subprocess.run(['go', 'build', '-o', str(binary), str(source)], check=True)
            result = subprocess.run([sys.executable, str(RUNNER), '--', str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('CONNECT api.awid.ai:443', result.stdout)


if __name__ == '__main__':
    unittest.main()
