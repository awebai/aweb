#!/usr/bin/env python3
"""Repository-wide private-infrastructure boundary gate for the public repo.

WHAT THIS CHECKS. Public aweb may talk to a hosted deployment; it may not carry
the hosted product's private surface. This gate enforces that distinction over
every Git-tracked decodable text file, not only docs/:

  1. hosted-only HTTP endpoints — an /api/v1 path the public OSS server and awid
     do not implement;
  2. hosted account-model schema fields — org_id and user_id, concepts the OSS
     product has no equivalent for, declared as JSON fields in public source;
  3. private repository and source paths;
  4. private documents and managed-gateway names: a private transition
     document's path, name or characteristic content, a managed-gateway
     private token in any path or text, a removed private or company-strategy
     path coming back, and a docs/ link into a private repository.

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

WHAT THIS DOES NOT CHECK. It cannot judge whether prose about a hosted service
is accurate — only whether private surface is present.
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
    # aw org/team/id create for signed-in users (aweb-acke, Juan direct 2026-10-22)
    "/api/v1/cli/identities",
    "/api/v1/cli/organizations",
    "/api/v1/cli/organizations/availability",
    "/api/v1/cli/teams",
    # Reached by public CLI source.
    "/api/v1/auth/namespaces",
    # Public CLI human-auth status check: aw auth status validates the narrow
    # aweb-cli / cli.workspace_team bearer against the hosted issuer.
    "/api/v1/cli-auth/status",
    "/api/v1/claim-human",
    "/api/v1/discovery",
    "/api/v1/onboarding/check-username",
    "/api/v1/onboarding/cli-signup",
    "/api/v1/spawn/accept-invite",
    # Public installed-root proof: aw team spawn-authority and default team
    # ensure verify that a selected certificate-authenticated identity can spawn.
    "/api/v1/spawn/authority",
    "/api/v1/spawn/create-invite",
    # Public non-redeeming inspection (aweb-abos/abor): possession-only preview
    # returns canonical team/scope/status/routing metadata, without hosted
    # account schemas. The new installed CLI capability requires Cloud support.
    "/api/v1/spawn/invite-preview",
    "/api/v1/teams/byoidt/projection-delete",
    # Public sibling-team creation (aweb-abkh.2): selected member certificate
    # authorizes a hosted service request; response is an ordinary invite plus
    # public team identifiers. No hosted account schema or private source paths.
    "/api/v1/teams/sibling",
    "/api/v1/workspaces/init",
    # Found only once the scan covered the whole corpus rather than CLI Go
    # source. The first derivation missed these: byoidt/import sits inside the
    # import-request help string rather than a request literal, and the rest
    # appear in tests, conformance vectors and the generated reference.
    "/api/v1/teams/byoidt/import",
    "/api/v1/teams/default",
    # Public workspace-team onboarding: aw team ensure first asks the hosted
    # service for the digest-bound default team, then enrolls a DID-key signed
    # local/global identity under that team. The CLI sends digest/proof material,
    # not hosted-private schemas or implementation paths.
    "/api/v1/teams/workspace-team/enroll",
    "/api/v1/teams/workspace-team/ensure",
    # Public shared-team admission: aw team admission-invite asks hosted aweb to
    # issue an ordinary single-use aw_inv_ for a team the human can write to.
    # The returned token is then consumed by existing invite-accept code.
    "/api/v1/teams/{team_id}/admission-invite",
    "/api/v1/network/directory",
    "/api/v1/network/directory/acme/researcher",
    "/api/v1/a2a/gateway/routes",
}

# --- baseline: hosted account-model schemas ----------------------------------
# Only org_id. It appears nowhere in this repository except the two baselined
# structs below, so it genuinely has no OSS meaning.
#
# user_id was a marker here and was WRONG: the OSS server uses it in
# internal_auth.py, team_auth.py and routes/dashboard.py, and aweb-sot.md
# documents it in a response shape. It is a real OSS concept, and the earlier
# scan only passed because it read cli/go source alone — widening the corpus
# without fixing the marker would have failed on the server immediately.
#
# api_key is excluded for the same reason and was caught earlier: workspace API
# keys are real OSS state throughout config and redaction code.
#
# Split so this file does not match itself.
HOSTED_ACCOUNT_FIELDS = ("org" + "_id",)
HOSTED_SCHEMA_BASELINE = {
    # Go declarations, keyed by struct name: moving one to another file keeps its
    # exemption, renaming it loses the exemption.
    "CliSignupResponse",
    "SpawnAcceptInviteResponse",
    # JSON fixtures that mock the hosted signup response for those structs. Keyed
    # by file because a JSON literal has no type name to key on — the weakest key
    # in this file, and stated as such. Renaming one, or adding a fifth, trips the
    # gate and needs its own decision.
    "cli/go/awid/onboarding_cli_signup_test.go",
    "cli/go/cmd/aw/hosted_signup_test.go",
    "cli/go/cmd/aw/init_inbound_mode_test.go",
    "cli/go/cmd/aw/onboarding_wizard_test.go",
}

# --- private repository and source paths -------------------------------------
# Split so this file does not match itself when it is scanned as part of the
# tracked corpus.
PRIVATE_PATH_MARKERS = (
    "backend/" + "src/aweb_cloud",
    "awebai/" + "aweb-saas",
    "aweb-" + "saas/backend",
)

# This class — and ONLY this class — has exclusions. They rest on two DIFFERENT
# arguments, and conflating them would exempt a future violation, so they are
# separate constants rather than one list.
#
# 1. agents/ is preserve-by-default by explicit ruling. It protects regardless of
#    content, because the content is stored operating knowledge whose absence is
#    invisible; only falsity justifies changing it. A gate that failed here could
#    not be satisfied by anyone acting within that rule. The test is the tree's
#    nature, so a prefix is the right shape.
PRIVATE_PATH_EXCLUDED_PREFIXES = ("agents/",)

# 2. This one file is excluded on entirely separate grounds: it is not product
#    documentation surface. The epic's constraint is that aweb *documentation*
#    must not name the private codebase; this is operator tooling for people
#    working in this repository, and a cross-repository coordination skill whose
#    subject is both repositories cannot do its job without naming the other
#    one's layout.
#
#    Deliberately a file and not a .claude/ prefix. A prefix would exempt every
#    future file placed there, unscanned, on grounds established for one skill —
#    the same shape as the archive exclusion that outlived its subject and
#    silently covered whatever arrived next. A new .claude/ file naming private
#    paths must trip this gate and get its own decision.
#
#    If a file under .claude/ ever teaches the product while naming private
#    internals, it fails this test — which the agents/ argument would have
#    wrongly protected.
PRIVATE_PATH_EXCLUDED_FILES = (".claude/skills/cross-repo-change/SKILL.md",)

# --- private documents and managed-gateway names -----------------------------
# Every literal is split so this file does not match itself. These rules have no
# exclusions: they apply to every tracked file, agents/ included.
PRIVATE_TRANSITION_PATHS = (
    "docs/restructuring/" + "ac-cross-boundary-" + "fk-inventory.md",
    "docs/support/" + "aasn-migration-" + "evidence-runbook.md",
)

PRIVATE_TRANSITION_PATH_NAMES = (
    "ac-cross-boundary-" + "fk-inventory",
    "aasn-migration-" + "evidence-runbook",
)

# A file matches a rule only when it carries every term of that rule.
PRIVATE_TRANSITION_CONTENT_RULES = (
    (
        "private database inventory",
        ("cross-boundary " + "foreign keys", "aweb_" + "cloud", "aweb_" + "overlay"),
    ),
    (
        "private production runbook",
        ("migration " + "evidence runbook", "production " + "stop conditions"),
    ),
    (
        "AC-only path/name",
        ("ac/backend/src/" + "aweb_cloud/migrations",),
    ),
    (
        "credentialed operator procedure",
        ("database_url=" + "service=", "pg_dump --" + "data-only"),
    ),
    (
        "private version/image baseline",
        ("production baseline: " + "ac", "server-v1."),
    ),
    (
        "private personnel approval flow",
        ("credentialed " + "human operator", "reviews this plan before execution"),
    ),
)

MANAGED_GATEWAY_PRIVATE_TOKENS = (
    "a" + "c_config",
    "a" + "c_base_url",
    "AWEB_A2A_GW_AC_" + "BASE_URL",
    "a2a-ac-" + "managed-gateway-contract",
    "a2a-gateway-ac-" + "managed",
    "a2a-gw-" + "ac",
    "a" + "c_config_expired",
    "/api/v1/a2a/gateway/" + "config",
    "AC-" + "managed",
    "AC runtime " + "config",
    "AC " + "bridge",
)

REMOVED_PRIVATE_PATHS = (
    "docs/" + "a2a-ac-" + "managed-gateway-contract.md",
    "docs/examples/" + "a2a-gateway-ac-" + "managed.yaml",
)

REMOVED_STRATEGY_PATHS = (
    "agents/souls/consultant/decisions/aweb-control-plane-and-apps.md",
    "agents/souls/consultant/docs/customer-centered-aweb-positioning.md",
    "agents/souls/consultant/memory/aweb-anapp-product-constraints.md",
    "docs/company-agent-platform-thesis.md",
    "docs/market-entry-wedge-research.md",
    "docs/website-dashboard-strategy.md",
)

# Links from public docs into private repositories.
PRIVATE_DOC_REFERENCES = ("../" + "ac", "ac/" + "docs/", "awebai/" + "naapp-specs")

SKIP_SUFFIXES = (".woff2", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf")


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=False, capture_output=True
    )
    if out.returncode != 0:
        raise SystemExit("cannot derive tracked corpus with git ls-files")
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def decodable_text(path: Path) -> str | None:
    """Text of a decodable file, or None for binary."""
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


# OSS services that live in this repository and serve their own routes. The
# public deployment mounts the aweb server under /api, so /api/v1/messages IS the
# server's /v1/messages; comparing literally would call every mounted route
# hosted-only.
OSS_SERVICE_SOURCES = ("server/src", "awid/src", "naapp")


def oss_served_endpoints(root: Path) -> set[str]:
    out = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "grep",
            "-rh",
            "-o",
            "-E",
            r"/(api/)?v1/[a-zA-Z0-9/_{}.\-]*",
            "--",
            *OSS_SERVICE_SOURCES,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        s.replace("/api/v1/", "/v1/")
        for s in out.stdout.split()
        if len(s.replace("/api/v1/", "/v1/")) > len("/v1/")
    }


def is_oss_route(endpoint: str, served: set[str]) -> bool:
    core = endpoint.replace("/api/v1/", "/v1/").rstrip("/")
    return any(
        core == s.rstrip("/") or core.startswith(s.rstrip("/") + "/") for s in served
    )


def normalized_endpoint(raw: str) -> str | None:
    """Trim prose punctuation; reject fragments that are not a whole endpoint."""
    endpoint = raw.rstrip(".,)\"'`")
    if "..." in endpoint or endpoint.endswith("/"):
        return None
    # A whole endpoint has at least three separators: the two in the prefix plus
    # one before its first segment. Requiring four dropped every single-segment
    # endpoint, which is how the first version of this rule lost three baselined
    # entries without failing.
    if endpoint.count("/") < 3:
        return None
    return endpoint


def cli_source_files(files: list[str]) -> list[str]:
    return [
        f
        for f in files
        if f.startswith("cli/go/")
        and f.endswith(".go")
        and "_test" not in f
        and "/testdata/" not in f
        and "/conformance/" not in f
    ]


def find_hosted_endpoints(root: Path, files: list[str]) -> dict[str, set[str]]:
    """Hosted-only endpoints anywhere in the corpus, not only in CLI Go source.

    An endpoint literal means the same thing in a YAML example, an OAS document
    or a Markdown code block as it does in Go, so the corpus is every tracked
    decodable file. An earlier version read CLI Go source alone and reported
    whole-corpus coverage it did not have.
    """
    served = oss_served_endpoints(root)
    found: dict[str, set[str]] = {}
    for rel in sorted(files):
        if rel.endswith(SKIP_SUFFIXES):
            continue
        text = decodable_text(root / rel)
        if text is None:
            continue
        for match in re.finditer(r"(/api/v1/[a-zA-Z0-9/_{}.\-]*)", text):
            endpoint = normalized_endpoint(match.group(1))
            if endpoint is None or is_oss_route(endpoint, served):
                continue
            found.setdefault(endpoint, set()).add(rel)
    return found


def find_hosted_schemas(root: Path, files: list[str]) -> dict[str, set[str]]:
    """Hosted account fields DECLARED as schema fields, anywhere in the corpus.

    Keyed on declaration rather than mention: prose naming the field — including
    the documentation of this gate — is describing it, not shipping it. In Go the
    declaration is attributed to its enclosing struct so the baseline can exempt
    known instances by name; on any other surface a declaration has no struct to
    belong to and is reported by file.
    """
    found: dict[str, set[str]] = {}
    for rel in sorted(files):
        if rel.endswith(SKIP_SUFFIXES):
            continue
        text = decodable_text(root / rel)
        if text is None:
            continue
        is_go = rel.endswith(".go") and "_test" not in rel
        current = None
        for line in text.splitlines():
            declared = re.match(r"^type (\w+) struct", line)
            if declared:
                current = declared.group(1)
            for field in HOSTED_ACCOUNT_FIELDS:
                go_decl = f'json:"{field}' in line
                data_decl = f'"{field}":' in line or re.search(rf"^\s*{field}:\s", line)
                if go_decl and is_go:
                    found.setdefault(current or rel, set()).add(rel)
                elif data_decl and not go_decl:
                    found.setdefault(rel, set()).add(rel)
    return found


def find_private_paths(root: Path, files: list[str]) -> list[str]:
    failures = []
    for rel in sorted(files):
        if rel.endswith(SKIP_SUFFIXES):
            continue
        if rel.startswith(PRIVATE_PATH_EXCLUDED_PREFIXES):
            continue
        if rel in PRIVATE_PATH_EXCLUDED_FILES:
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


def find_private_documents(root: Path, files: list[str]) -> list[str]:
    failures = []
    for rel in sorted(files):
        lowered_rel = rel.casefold()
        for token in MANAGED_GATEWAY_PRIVATE_TOKENS:
            if token.casefold() in lowered_rel:
                failures.append(
                    f"tracked path {rel} retains private managed-gateway name {token!r}"
                )
        for name in PRIVATE_TRANSITION_PATH_NAMES:
            if name.casefold() in lowered_rel:
                failures.append(
                    f"tracked path {rel} retains private transition document name"
                )

        path = root / rel
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        # Tokens are searched in every non-binary file, even one that is not UTF-8.
        lowered = raw.decode("utf-8", errors="replace").casefold()
        for token in MANAGED_GATEWAY_PRIVATE_TOKENS:
            if token.casefold() in lowered:
                failures.append(
                    f"{rel} retains private managed-gateway token {token!r}"
                )
        text = decodable_text(path)
        if text is None:
            continue
        lowered = text.casefold()
        for name in PRIVATE_TRANSITION_PATH_NAMES:
            if name.casefold() in lowered:
                failures.append(
                    f"tracked file {rel} references private transition document name"
                )
        for label, terms in PRIVATE_TRANSITION_CONTENT_RULES:
            if all(term.casefold() in lowered for term in terms):
                failures.append(f"{rel} retains {label}")
        if rel.startswith("docs/") and rel.endswith(".md"):
            for reference in PRIVATE_DOC_REFERENCES:
                if reference in text:
                    failures.append(
                        f"{rel} references a private repository: {reference!r}"
                    )

    for rel in PRIVATE_TRANSITION_PATHS:
        if (root / rel).exists():
            failures.append(f"removed private transition path returned: {rel}")
    for rel in REMOVED_PRIVATE_PATHS:
        if (root / rel).exists():
            failures.append(f"removed private managed-gateway path returned: {rel}")
    for rel in REMOVED_STRATEGY_PATHS:
        if (root / rel).exists():
            failures.append(f"removed company-strategy path returned: {rel}")
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
    failures.extend(find_private_documents(root, files))
    return failures


def derive(root: Path) -> int:
    """Print a freshly measured baseline. Never writes; the file is edited by hand.

    This is an aid to classification, not a generator. OSS routes are recognised
    by grepping service source for path fragments, and a router registers its
    prefix and its paths separately — so matching a prefix can suppress a hosted
    route that merely lives under a shared one. The workspaces prefix is a real
    instance: the OSS server serves /v1/workspaces but has no init route, and
    the hosted init endpoint disappears from this output because of it.

    So entries in the committed baseline that this no longer finds are printed
    too. Each is either coupling that was removed — delete it, and the gate gets
    stricter — or an endpoint this heuristic is suppressing. Silence would make
    those indistinguishable.
    """
    files = tracked_files(root)
    print("HOSTED_ENDPOINT_BASELINE = {")
    for endpoint in sorted(find_hosted_endpoints(root, files)):
        print(f'    "{endpoint}",')
    print("}\n")
    print("HOSTED_SCHEMA_BASELINE = {")
    for schema in sorted(find_hosted_schemas(root, files)):
        print(f'    "{schema}",')
    print("}")

    endpoints = set(find_hosted_endpoints(root, files))
    schemas = set(find_hosted_schemas(root, files))
    unfound = sorted(
        (HOSTED_ENDPOINT_BASELINE - endpoints) | (HOSTED_SCHEMA_BASELINE - schemas)
    )
    if unfound:
        print("\n# committed baseline entries this run did not find — each is either")
        print("# coupling that is gone (delete the entry) or one this heuristic")
        print("# suppresses (keep it, and see the docstring):")
        for entry in unfound:
            print(f"#   {entry}")
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
        invented = "/api/v1/onboarding/" + "invented-endpoint"
        write("cli/go/awid/new.go", f'const p = "{invented}"\n')
        failures = check(tmp)
        if not any(invented in f for f in failures):
            print("self-test failed: an endpoint outside the baseline was not rejected")
            return 1
        (tmp / "cli/go/awid/new.go").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # A new struct carrying the hosted account model must fail, by name and
        # regardless of file — the property that makes this a baseline and not a
        # location allowlist.
        write(
            "cli/go/cmd/aw/elsewhere.go",
            "type InventedAccountResponse struct {\n"
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
            print(
                f"self-test failed: baselined schema rejected after moving: {failures[0]}"
            )
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

        # The file exclusion covers exactly its file. A sibling under the same
        # directory must still fail, or it is a prefix exclusion wearing a
        # filename.
        for rel in PRIVATE_PATH_EXCLUDED_FILES:
            write(rel, "see " + "backend/" + "src/aweb_cloud/x\n")
            if any("private repository path" in f for f in check(tmp)):
                print(f"self-test failed: {rel} was expected to be excluded")
                return 1
            sibling = str(Path(rel).parent / "OTHER.md")
            write(sibling, "see " + "backend/" + "src/aweb_cloud/x\n")
            if not any("private repository path" in f for f in check(tmp)):
                print("self-test failed: the file exclusion covered a sibling")
                return 1
            (tmp / rel).unlink()
            (tmp / sibling).unlink()
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

        # Private documents and managed-gateway names. Each rule is proven on a
        # docs/ file and on a non-document surface, and binary or undecodable
        # bytes are not read as text.
        transition_fixtures = {
            "private database inventory": (
                "Cross-boundary "
                + "foreign keys\naweb_"
                + "cloud rows\naweb_"
                + "overlay changes\n",
                "skills/transition-evidence/SKILL.md",
            ),
            "private production runbook": (
                "Migration " + "evidence runbook\nProduction " + "stop conditions\n",
                "scripts/self-test-transition-evidence.sh",
            ),
            "AC-only path/name": (
                "ac/backend/src/" + "aweb_cloud/migrations/001.sql\n",
                "channel/self-test-package.json",
            ),
            "credentialed operator procedure": (
                "DATABASE_URL=" + "service=production\npg_dump --" + "data-only\n",
                "deploy/self-test-operator.yaml",
            ),
            "private version/image baseline": (
                "Production baseline: " + "AC v9.9.9\nserver-v1.2.3\n",
                "server/tests/fixtures/self-test-baseline.txt",
            ),
            "private personnel approval flow": (
                "Credentialed "
                + "human operator\nReviewer reviews this plan before execution\n",
                "cli/go/npm/self-test-approval.js",
            ),
        }
        if set(transition_fixtures) != {
            label for label, _ in PRIVATE_TRANSITION_CONTENT_RULES
        }:
            print("self-test failed: every private transition rule needs a fixture")
            return 1

        def rejects(expected: str) -> bool:
            return any(expected in failure for failure in check(tmp))

        def remove(rel: str) -> None:
            (tmp / rel).unlink()
            subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        for index, (label, (content, surface)) in enumerate(
            transition_fixtures.items()
        ):
            for rel in (f"docs/private-transition-{index}.md", surface):
                write(rel, content)
                if not rejects(f"{rel} retains {label}"):
                    print(f"self-test failed: {label} was not rejected in {rel}")
                    return 1
                remove(rel)
            rel = f"server/tests/fixtures/private-transition-{index}.bin"
            for raw_bytes in (
                b"\0\x1f\x8b" + content.encode("utf-8") + b"\0",
                "Príväte".encode("latin-1") + content.encode("utf-8"),
            ):
                (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
                (tmp / rel).write_bytes(raw_bytes)
                subprocess.run(["git", "-C", str(tmp), "add", rel], check=True)
                if rejects(f"{rel} retains"):
                    print(
                        f"self-test failed: binary or undecodable {label} was read as text"
                    )
                    return 1
            remove(rel)

        for index, name in enumerate(PRIVATE_TRANSITION_PATH_NAMES):
            rel = f"reviewer/{name}-{index}.md"
            write(rel, "generic: true\n")
            if not rejects(
                f"tracked path {rel} retains private transition document name"
            ):
                print(
                    f"self-test failed: private transition name was not rejected: {rel}"
                )
                return 1
            remove(rel)
            rel = f"reviewer/private-transition-consumer-{index}.txt"
            write(rel, f"docs/archive/{name}.md\n")
            if not rejects(
                f"tracked file {rel} references private transition document name"
            ):
                print(f"self-test failed: a reference to {name} was not rejected")
                return 1
            remove(rel)

        for index, token in enumerate(MANAGED_GATEWAY_PRIVATE_TOKENS):
            for rel in ("README.md", f"cli/go/internal/a2a/surface-{index}.go"):
                write(rel, f"generic\n{token}\n")
                if not rejects(f"{rel} retains private managed-gateway token"):
                    print(
                        f"self-test failed: managed-gateway token {token!r} was not rejected in {rel}"
                    )
                    return 1
                remove(rel)
        for rel in (
            "docs/examples/A2A-GW-" + "AC.yaml",
            "reviewer/AC_" + "CONFIG.go",
            "docs/examples/a2a-ac-" + "managed-gateway-contract-copy.yaml",
        ):
            write(rel, "generic: true\n")
            if not rejects(f"tracked path {rel} retains private managed-gateway name"):
                print(
                    f"self-test failed: private managed-gateway path was not rejected: {rel}"
                )
                return 1
            remove(rel)

        for rel, expected in (
            *(
                (rel, "removed private transition path returned")
                for rel in PRIVATE_TRANSITION_PATHS
            ),
            *(
                (rel, "removed private managed-gateway path returned")
                for rel in REMOVED_PRIVATE_PATHS
            ),
            *(
                (rel, "removed company-strategy path returned")
                for rel in REMOVED_STRATEGY_PATHS
            ),
        ):
            # Existence is enough: an untracked file in its old place still fails.
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp / rel).write_text("generic: true\n", encoding="utf-8")
            if not rejects(f"{expected}: {rel}"):
                print(f"self-test failed: {rel} returned without failing")
                return 1
            (tmp / rel).unlink()

        for reference in PRIVATE_DOC_REFERENCES:
            rel = "docs/linking.md"
            write(rel, f"[private]({reference}/x.md)\n")
            if not rejects(f"{rel} references a private repository"):
                print(
                    f"self-test failed: a docs link to {reference!r} was not rejected"
                )
                return 1
            remove(rel)

    print(
        "self-test passed: the baseline admits its known instances, rejects a new "
        "endpoint, a new account schema and a renamed one, follows a baselined "
        "schema across files, rejects private paths on non-source surfaces, keeps "
        "the file exclusion off a sibling in the same directory, skips binary "
        "content, and rejects private transition documents, managed-gateway names, "
        "returned private or strategy paths and private links from docs"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", default=Path(__file__).resolve().parents[1], type=Path
    )
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
    print(
        "public repository carries no private infrastructure outside the frozen baseline"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
