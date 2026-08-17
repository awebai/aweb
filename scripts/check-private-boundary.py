#!/usr/bin/env python3
"""Repository-wide private-infrastructure boundary gate for the public repo.

WHAT THIS CHECKS. Public aweb may talk to a hosted deployment; it may not carry
the hosted product's private surface. This gate enforces that distinction over
every Git-tracked decodable text file, not only docs/:

  1. hosted-only HTTP endpoints — an /api/v1 path the public OSS server and awid
     do not implement;
  2. hosted account-model schema fields — org_id and user_id, concepts the OSS
     product has no equivalent for, declared as JSON fields in public source;
  3. private repository and source paths.

BASELINE, NOT ALLOWLIST — the distinction matters and .9.1 forbids the other one.
An allowlist exempts LOCATIONS: "anything under cli/go/awid/ may do this." A
baseline exempts KNOWN INSTANCES: "these ten exact endpoint literals and these
two exact struct names are known, measured and frozen." Move the coupling to a
new file and the gate still trips, because the baseline never mentions where the
instance lives. Add an eleventh endpoint and it trips, because the baseline is
enumerated rather than patterned.

The baseline exists because aweb-aazb.11 was retired: the coupling is real,
Juan decided not to fix it now, and a gate that failed on it would be red on main
by design. Freezing the measured set keeps the gate meaningful for everything new.

IT MUST SHRINK SILENTLY AND NEVER GROW SILENTLY. Removing an entry when coupling
is actually fixed makes this stricter with no other change and needs no
discussion. Adding one is a visible diff in this file and should be argued for in
review, not regenerated.

WHAT THIS DOES NOT CHECK. Managed-gateway private tokens and private-transition
document content are enforced by check-extension-docs.py, which owns those
classes and their fixtures. This gate does not duplicate them. It also cannot
judge whether prose about a hosted service is accurate — only whether private
surface is present.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# --- baseline: hosted-only endpoints -----------------------------------------
# Measured against origin/main by taking every /api/v1 literal in non-test CLI Go
# source and removing those the public server or awid implements. Re-derive with
# --derive rather than editing by hand.
HOSTED_ENDPOINT_BASELINE = {
    "/api/v1/auth/namespaces",
    "/api/v1/claim-human",
    "/api/v1/discovery",
    "/api/v1/onboarding/bootstrap-redeem",
    "/api/v1/onboarding/check-username",
    "/api/v1/onboarding/cli-signup",
    "/api/v1/spawn/accept-invite",
    "/api/v1/spawn/create-invite",
    "/api/v1/teams/byoidt/projection-delete",
    "/api/v1/workspaces/init",
}

# --- baseline: hosted account-model schemas ----------------------------------
# org_id and user_id model the hosted product's account, which the OSS product
# does not have. api_key is deliberately NOT a marker: workspace API keys are a
# real OSS concept and appear throughout config and redaction code.
HOSTED_ACCOUNT_FIELDS = ("org_id", "user_id")
HOSTED_SCHEMA_BASELINE = {
    "CliSignupResponse",
    "SpawnAcceptInviteResponse",
}

# --- private repository and source paths -------------------------------------
# Split so this file does not match itself when it is scanned as part of the
# tracked corpus.
PRIVATE_PATH_MARKERS = (
    "backend/" + "src/aweb_cloud",
    "awebai/" + "aweb-saas",
    "aweb-" + "saas/backend",
)

# This class — and ONLY this class — excludes the repository's own agent
# operating material. Stated plainly because it is a location exclusion, which
# the hosted-coupling baselines above deliberately are not:
#
#   - agents/ is preserve-by-default by explicit ruling: only falsity justifies
#     a change there, so a gate that fails on it cannot be satisfied by anyone
#     acting within that rule;
#   - .claude/skills/cross-repo-change/ exists to coordinate changes spanning
#     the OSS and hosted repositories. Naming the other repository's layout is
#     the skill's subject, not leakage into product surface.
#
# Neither is published product surface. The two current instances were measured
# and reported rather than silently absorbed; see aweb-aazb.9.1. If agent
# material ever ships as a product artifact, this exclusion stops being correct.
PRIVATE_PATH_EXCLUDED_PREFIXES = ("agents/", ".claude/")

SKIP_SUFFIXES = (".woff2", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf")


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=False, capture_output=True
    )
    if out.returncode != 0:
        raise SystemExit("cannot derive tracked corpus with git ls-files")
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def decodable_text(path: Path) -> str | None:
    """Text of a decodable file, or None for binary. Mirrors check-extension-docs."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def oss_served_endpoints(root: Path) -> set[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "grep", "-rh", "-o", "-E",
         r"/api/v1/[a-zA-Z0-9/_{}.\-]*", "--", "server/src", "awid/src"],
        check=False, capture_output=True, text=True,
    )
    return {s for s in out.stdout.split() if len(s) > len("/api/v1/")}


def cli_source_files(files: list[str]) -> list[str]:
    return [
        f for f in files
        if f.startswith("cli/go/") and f.endswith(".go")
        and "_test" not in f and "/testdata/" not in f and "/conformance/" not in f
    ]


def find_hosted_endpoints(root: Path, files: list[str]) -> dict[str, set[str]]:
    served = oss_served_endpoints(root)
    found: dict[str, set[str]] = {}
    for rel in cli_source_files(files):
        text = decodable_text(root / rel)
        if text is None:
            continue
        for match in re.finditer(r'"(/api/v1/[a-zA-Z0-9/_{}.\-]*)"', text):
            endpoint = match.group(1)
            if any(s.startswith(endpoint.rstrip("/")) or endpoint.startswith(s.rstrip("/"))
                   for s in served):
                continue
            found.setdefault(endpoint, set()).add(rel)
    return found


def find_hosted_schemas(root: Path, files: list[str]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for rel in cli_source_files(files):
        text = decodable_text(root / rel)
        if text is None:
            continue
        current = None
        for line in text.splitlines():
            declared = re.match(r"^type (\w+) struct", line)
            if declared:
                current = declared.group(1)
            for field in HOSTED_ACCOUNT_FIELDS:
                if f'json:"{field}' in line and current:
                    found.setdefault(current, set()).add(rel)
    return found


def find_private_paths(root: Path, files: list[str]) -> list[str]:
    failures = []
    for rel in sorted(files):
        if rel.endswith(SKIP_SUFFIXES):
            continue
        if rel.startswith(PRIVATE_PATH_EXCLUDED_PREFIXES):
            continue
        path = root / rel
        if not path.is_file():
            continue
        text = decodable_text(path)
        if text is None:
            continue
        lowered = text.casefold()
        for marker in PRIVATE_PATH_MARKERS:
            if marker.casefold() in lowered:
                failures.append(f"{rel} references private repository path {marker!r}")
    return failures


def check(root: Path) -> list[str]:
    files = tracked_files(root)
    failures: list[str] = []

    endpoints = find_hosted_endpoints(root, files)
    for endpoint in sorted(set(endpoints) - HOSTED_ENDPOINT_BASELINE):
        where = ", ".join(sorted(endpoints[endpoint]))
        failures.append(
            f"hosted-only endpoint outside the baseline: {endpoint} ({where})"
        )

    schemas = find_hosted_schemas(root, files)
    for schema in sorted(set(schemas) - HOSTED_SCHEMA_BASELINE):
        where = ", ".join(sorted(schemas[schema]))
        failures.append(
            f"hosted account-model schema outside the baseline: {schema} ({where})"
        )

    failures.extend(find_private_paths(root, files))
    return failures


def derive(root: Path) -> int:
    """Print a freshly measured baseline. Never writes; the file is edited by hand."""
    files = tracked_files(root)
    print("HOSTED_ENDPOINT_BASELINE = {")
    for endpoint in sorted(find_hosted_endpoints(root, files)):
        print(f'    "{endpoint}",')
    print("}\n")
    print("HOSTED_SCHEMA_BASELINE = {")
    for schema in sorted(find_hosted_schemas(root, files)):
        print(f'    "{schema}",')
    print("}")
    return 0


def self_test(root: Path) -> int:
    if failures := check(root):
        print("self-test setup is not green:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], check=True)

        def write(rel: str, body: str) -> None:
            path = tmp / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            subprocess.run(["git", "-C", str(tmp), "add", rel], check=True)

        # A clean fixture with a baseline member must pass: the baseline works.
        write("cli/go/awid/known.go", 'const p = "/api/v1/onboarding/cli-signup"\n')
        if failures := check(tmp):
            print(f"self-test failed: baseline member was rejected: {failures[0]}")
            return 1

        # An eleventh hosted endpoint must fail. This is the control that makes
        # the green run above mean something: without it, a gate whose baseline
        # covers everything is indistinguishable from one that cannot fail.
        write("cli/go/awid/new.go", 'const p = "/api/v1/onboarding/invented-endpoint"\n')
        failures = check(tmp)
        if not any("invented-endpoint" in f for f in failures):
            print("self-test failed: an endpoint outside the baseline was not rejected")
            return 1
        (tmp / "cli/go/awid/new.go").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # A new struct carrying the hosted account model must fail, by name and
        # regardless of file — the property that makes this a baseline and not a
        # location allowlist.
        write(
            "cli/go/cmd/aw/elsewhere.go",
            'type InventedAccountResponse struct {\n'
            '\tOrgID string `json:"org_id"`\n}\n',
        )
        failures = check(tmp)
        if not any("InventedAccountResponse" in f for f in failures):
            print("self-test failed: a new hosted account schema was not rejected")
            return 1
        (tmp / "cli/go/cmd/aw/elsewhere.go").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # A baselined schema keeps its exemption when it moves file, and loses it
        # when it is renamed.
        write(
            "cli/go/cmd/aw/moved.go",
            'type CliSignupResponse struct {\n\tOrgID string `json:"org_id"`\n}\n',
        )
        if failures := check(tmp):
            print(f"self-test failed: baselined schema rejected after moving: {failures[0]}")
            return 1
        write(
            "cli/go/cmd/aw/moved.go",
            'type CliSignupResponseV2 struct {\n\tOrgID string `json:"org_id"`\n}\n',
        )
        if not any("CliSignupResponseV2" in f for f in check(tmp)):
            print("self-test failed: a renamed hosted schema was not rejected")
            return 1
        (tmp / "cli/go/cmd/aw/moved.go").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # Private repository paths fail anywhere in the tracked corpus, including
        # non-source surfaces.
        write("skills/example/SKILL.md", "see " + "ac/backend/" + "src/aweb_cloud/x\n")
        if not any("private repository path" in f for f in check(tmp)):
            print("self-test failed: a private repository path was not rejected")
            return 1
        (tmp / "skills/example/SKILL.md").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # The agent-material exclusion is narrow: identical content passes under
        # an excluded prefix and fails immediately outside it. Without both
        # halves this is an exclusion nobody has measured.
        for excluded in PRIVATE_PATH_EXCLUDED_PREFIXES:
            rel = f"{excluded}probe/note.md"
            write(rel, "see " + "backend/" + "src/aweb_cloud/x\n")
            if any("private repository path" in f for f in check(tmp)):
                print(f"self-test failed: {excluded} was expected to be excluded")
                return 1
            (tmp / rel).unlink()
            subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
        write("server/src/probe.py", "# see " + "backend/" + "src/aweb_cloud/x\n")
        if not any("private repository path" in f for f in check(tmp)):
            print("self-test failed: the exclusion leaked outside agent material")
            return 1
        (tmp / "server/src/probe.py").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # Binary content is skipped explicitly rather than coerced to text.
        (tmp / "asset.bin").write_bytes(b"\0" + b"ac/backend/" + b"src/aweb_cloud\0")
        subprocess.run(["git", "-C", str(tmp), "add", "asset.bin"], check=True)
        if any("private repository path" in f for f in check(tmp)):
            print("self-test failed: binary content was scanned as text")
            return 1

    print(
        "self-test passed: the baseline admits its known instances, rejects a new "
        "endpoint, a new account schema and a renamed one, follows a baselined "
        "schema across files, rejects private paths on non-source surfaces, and "
        "skips binary content"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--derive", action="store_true")
    args = parser.parse_args()

    if args.derive:
        return derive(args.root)
    if args.self_test:
        return self_test(args.root)

    failures = check(args.root)
    if failures:
        print("private-infrastructure boundary violations:")
        for failure in failures:
            print(f"- {failure}")
        print(
            "\nIf this is genuinely new hosted coupling, it needs a decision, not a "
            "baseline entry. If the coupling was removed, delete its baseline entry "
            "instead — that makes this gate stricter."
        )
        return 1
    print("public repository carries no private infrastructure outside the frozen baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
