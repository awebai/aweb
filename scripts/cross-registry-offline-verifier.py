"""Outside verification: only exported public bytes, DNS and AWID are available."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    mode, human = sys.argv[1:]
    adopted = Path("/envelopes/adopted.json").read_text()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        # No inherited tokens, config, identity-home selector, proxy or server URL.
        # The container mounts only the public export directory, never a .aw.
        # APP_ENV only permits this fixture's HTTP registry origin. Explicit
        # --registry selects its private address through the supported operator
        # path; no federation-test bypass, TLS bypass or DNS verifier is used.
        env = {"HOME": str(home), "PATH": os.environ["PATH"],
               "APP_ENV": "development"}

        def verify(raw, *, stdin=False, text=False):
            args = ["aw", "verify", "--registry", "http://awid-a:8010"]
            if not text:
                args.append("--json")
            if not stdin:
                path = root / "message.json"
                path.write_text(raw)
                args.append(str(path))
            result = subprocess.run(args, input=raw if stdin else None, text=True,
                                    capture_output=True, cwd=root, env=env, timeout=30)
            assert result.returncode == 0, (args, result.stdout, result.stderr)
            assert not list(home.iterdir()), list(home.iterdir())
            assert not (root / ".aw").exists()
            return result.stdout if text else json.loads(result.stdout)

        def no_authority(result):
            assert result["identity_valid"] is not True, result
            assert result["human_id"] is None and result["kind"] is None, result
            assert "chain" not in result, result

        if mode == "controls":
            result = verify(adopted)
            assert result["outcome"] == "nearest_human", result
            assert result["identity_valid"] is True and result["human_id"] == human, result
            assert result["kind"] == "agent" and result["reason"] == "verified", result
            assert verify(adopted, stdin=True) == result
            assert human in verify(adopted, text=True)
            print("PASS: exported adopted agent verifies from file and stdin with no credentials")

            plain = Path("/envelopes/chainless.json").read_text()
            result = verify(plain)
            no_authority(result)
            assert result["outcome"] == "unknown", result
            assert result["reason"] == "unregistered_identity", result
            assert result["identity_valid"] is None, result
            print("PASS: exported chainless agent remains unknown, without an inferred human")

            tampered = json.loads(adopted)
            payload = json.loads(tampered["signed_payload"])
            payload["body"] = "tampered after export"
            tampered["signed_payload"] = json.dumps(payload)
            raw = json.dumps(tampered)
            result = verify(raw, stdin=True)
            no_authority(result)
            assert result["outcome"] == "unknown" and result["identity_valid"] is False, result
            assert "invalid" in verify(raw, text=True).lower()
            print("PASS: tampered exported message is invalid before it can establish a human")
        elif mode == "unavailable":
            result = verify(adopted)
            no_authority(result)
            assert result["outcome"] == "unavailable", result
            assert result["reason"] == "evidence_unavailable", result
            print("PASS: stopped real registry gives unavailable, never valid")
        elif mode == "dns-root":
            result = verify(adopted)
            no_authority(result)
            assert result["identity_valid"] is False or result["outcome"] == "unavailable", result
            print("PASS: changed authoritative DNS root gives invalid or unavailable, never valid")
        else:
            raise AssertionError(mode)


if __name__ == "__main__":
    main()
