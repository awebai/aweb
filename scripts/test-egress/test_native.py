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
sys.path.insert(0, str(RUNNER.parent))
import native  # noqa: E402


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


    def test_denial_names_the_client_process_without_its_arguments(self):
        # A test's own temporary directory names it, as Go's t.TempDir does;
        # the child's argument stands in for a credential on a command line.
        with tempfile.TemporaryDirectory() as tmp:
            test_dir = (Path(tmp) / 'TestEgressAttributionProbe123' / '001').resolve()
            test_dir.mkdir(parents=True)
            pid_file = test_dir / 'pid'
            code = ('import os, sys, urllib.request\n'
                    f'open({str(pid_file)!r}, "w").write(str(os.getpid()))\n'
                    # It waits for the guard's answer: a client that gave up
                    # would exit while the guard is still naming it.
                    'try:\n urllib.request.urlopen("https://api.awid.ai/v1/did", timeout=30)\n'
                    'except OSError:\n pass\n')
            result = subprocess.run(
                [sys.executable, str(RUNNER), '--', sys.executable, '-c', code, 'secret-token-arg'],
                capture_output=True, text=True, cwd=test_dir, timeout=30)
            pid = pid_file.read_text()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        denied = [line for line in result.stdout.splitlines() if 'CONNECT api.awid.ai:443' in line]
        self.assertEqual(len(denied), 1, result.stdout)
        self.assertIn(f'client=pid={pid} exe=', denied[0])
        self.assertIn(f'cwd={test_dir}', denied[0])
        self.assertNotIn('secret-token-arg', result.stdout + result.stderr)

    def test_a_client_that_exits_during_attribution_is_named_as_exited(self):
        # A real child, exited and reaped: the guard reads nothing of it, and
        # says so instead of reporting an unknown working directory.
        child = subprocess.run([sys.executable, '-c', 'import os; print(os.getpid())'],
                               capture_output=True, text=True, check=True)
        pid = int(child.stdout)
        with self.assertRaises(ProcessLookupError):
            native.process_facts(pid)
        self.assertEqual(native.process_chain(pid, guard_child=None),
                         f'client=pid={pid} exited during attribution')

if __name__ == '__main__':
    unittest.main()
