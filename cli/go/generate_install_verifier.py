#!/usr/bin/env python3
"""Generate the shell's signed-manifest verifier from the publisher's owner."""

import argparse
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
START = "# BEGIN GENERATED RELEASE VERIFIER"
END = "# END GENERATED RELEASE VERIFIER"


def _render_verifier(keys):
    owner = (ROOT / "release_manifest.py").read_text()
    # Includes strict JSON, signature, version and artifact verification, without
    # publication/readback commands. No downloaded program is ever executed.
    program = owner[
        owner.index("from __future__") : owner.index("def create_manifest(")
    ]
    return (
        START + "\nverify_signed_release() {\n"
        "    if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then\n"
        '        log_error "Cannot verify $1. Install Python 3 and OpenSSL with Ed25519 support, then retry the installer."\n'
        "        return 1\n    fi\n"
        '    python3 - "$1" "$2" "$3" "$4" <<\'PY\'\n' + program + "import sys\ntry:\n"
        f"    keys = json.loads({keys!r}, object_pairs_hook=unique_object)\n"
        "    artifact, manifest_path, signature_path, requested = sys.argv[1:]\n"
        "    manifest = verify_manifest(manifest_bytes=Path(manifest_path).read_bytes(), signature_bytes=Path(signature_path).read_bytes(), keys=keys, requested_version=requested)\n"
        "    verify_artifact(Path(artifact), manifest)\n"
        "except (OSError, ValueError, KeyError, TypeError) as error:\n"
        '    print(f"Cannot verify {sys.argv[1]}: {error}. Retry the installer from a current signed release.", file=sys.stderr)\n'
        "    raise SystemExit(1)\nPY\n}\n" + END + "\n\n"
    )


def generated(keys=None):
    if keys is None:
        keys = (ROOT / "internal/releaseverify/keys.json").read_text().strip()
    pins = json.loads(keys)
    if (
        len(pins) not in (0, 2)
        or any(len(base64.b64decode(key, validate=True)) != 32 for key in pins.values())
        or len(set(pins.values())) != len(pins)
    ):
        raise ValueError("release pins require two distinct Ed25519 public keys")
    return _render_verifier(keys)


def proof_verifier(keys):
    """Use the identical shell verifier with one external proof-only public pin."""
    pins = json.loads(keys)
    if len(pins) != 1 or any(
        len(base64.b64decode(key, validate=True)) != 32 for key in pins.values()
    ):
        raise ValueError("proof requires one Ed25519 public key")
    return _render_verifier(keys)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "install.sh"
    current = path.read_text()
    if START in current:
        start, end = current.index(START), current.index(END) + len(END)
        while end < len(current) and current[end] == "\n":
            end += 1
    else:
        start = end = current.index("# Returns a list of full paths")
    wanted = current[:start] + generated() + current[end:]
    if args.check:
        if wanted != current:
            raise SystemExit(
                "install.sh release verifier is stale; run python3 cli/go/generate_install_verifier.py"
            )
    else:
        path.write_text(wanted)


if __name__ == "__main__":
    main()
