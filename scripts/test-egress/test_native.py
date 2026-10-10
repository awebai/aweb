"""Real subprocess controls: no mocked transport or service responses."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).with_name('native.py')


class NativeGuard(unittest.TestCase):
    def run_request(self, url, method='GET'):
        code = ('import urllib.request\n'
                f'req = urllib.request.Request({url!r}, method={method!r})\n'
                'try:\n urllib.request.urlopen(req, timeout=2)\n'
                'except OSError:\n pass\n')
        return subprocess.run([sys.executable, str(RUNNER), '--', sys.executable, '-c', code], capture_output=True, text=True)

    def test_swallowed_production_write_fails(self):
        result = self.run_request('https://api.awid.ai/v1/did/test/encryption-key', 'POST')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('CONNECT api.awid.ai:443', result.stdout)

    def test_reserved_refused_without_violation(self):
        result = self.run_request('https://app.example/discovery')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('TEST EGRESS DENIED', result.stdout)

    def test_allowlisted_https_is_refused_and_reported(self):
        result = self.run_request('https://app.aweb.ai/anything', 'POST')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('CONNECT app.aweb.ai:443', result.stdout)

    def test_allowlisted_plain_http_write_fails(self):
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
