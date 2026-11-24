#!/usr/bin/env python3
"""The published naapp image pins that aweb's app journeys run."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / "scripts/app_images.py"
DIGEST = "0123456789abcdef" * 4


def read(name, pins):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "app-images.json"
        path.write_text(json.dumps(pins))
        return subprocess.run([sys.executable, str(READER), "--pins", str(path), name],
                              text=True, capture_output=True)


class AppImagesTests(unittest.TestCase):
    def test_committed_pins_name_each_journey_image_by_digest(self):
        pins = json.loads((ROOT / "tools/app-images.json").read_text())
        self.assertEqual(set(pins), {"folio", "library"})
        for name, reference in pins.items():
            with self.subTest(name=name):
                self.assertTrue(reference.startswith(f"ghcr.io/awebai/{name}@sha256:"), reference)

    def test_pinned_digest_prints_the_exact_reference(self):
        reference = f"ghcr.io/awebai/folio@sha256:{DIGEST}"
        result = read("folio", {"folio": reference})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, reference + "\n")
        self.assertEqual(result.stderr, "")

    def test_empty_digest_refuses_as_unpublished(self):
        result = read("library", {"library": "ghcr.io/awebai/library@sha256:"})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("tools/app-images.json pins no digest for ghcr.io/awebai/library", result.stderr)
        self.assertIn("the naapp image is not yet published", result.stderr)

    def test_reference_without_an_exact_digest_is_refused(self):
        for reference in ("ghcr.io/awebai/folio:latest", "ghcr.io/awebai/folio@sha256:abc",
                          f"ghcr.io/awebai/folio:1.0@sha256:{DIGEST}", f"ghcr.io/awebai/library@sha256:{DIGEST}"):
            with self.subTest(reference=reference):
                result = read("folio", {"folio": reference})
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("tools/app-images.json", result.stderr)

    def test_unknown_image_is_refused(self):
        result = read("logs", {"folio": f"ghcr.io/awebai/folio@sha256:{DIGEST}"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("tools/app-images.json names no logs image", result.stderr)


if __name__ == "__main__":
    unittest.main()
