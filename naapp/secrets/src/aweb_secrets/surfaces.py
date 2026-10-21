"""Secrets' public copy on the shared naapp chrome and manifest-driven docs.

Landing wording: copy v1 approved by Juan, 2026-10-21. Public docs are mounted
only on the API app by the composition owner; the passkey console is separate.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from html import escape
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aweb_naapp as naapp
from aweb_naapp.skills import Skills

from aweb_secrets.manifest import MANIFEST

if TYPE_CHECKING:
    from aweb_naapp.runtime.app import NaappRuntime
    from aweb_naapp.runtime.health import HealthCheck
    from fastapi import FastAPI

_PACKAGE = Path(__file__).resolve().parent
SKILLS = Skills(app_name="secrets", env_var="SECRETS_SKILLS_DIR", source_dir=_PACKAGE / "skills")


def _site(
    *, public_origin: str, console_origin: str, title: str, description: str
) -> naapp.SiteConfig:
    return naapp.SiteConfig(
        origin=public_origin.rstrip("/"),
        brand="secrets",
        title=title,
        description=description,
        nav_links=(
            naapp.NavLink("Reference", "/reference"),
            naapp.NavLink("Skills", "/skills/"),
            naapp.NavLink("awid", "https://awid.ai"),
            naapp.NavLink("aweb", "https://aweb.ai"),
        ),
        footer_blurb=(
            "Controlled credential use for agent teams — grants, passkey "
            "approvals, brokered calls and pinned runner jobs."
        ),
        footer_columns=(
            naapp.FooterColumn(
                "Agents",
                (
                    naapp.NavLink("llms.txt", "/llms.txt"),
                    naapp.NavLink("API reference", "/reference"),
                    naapp.NavLink("Skills", "/skills/"),
                    naapp.NavLink("App manifest", "/aweb-app.json"),
                ),
            ),
            naapp.FooterColumn(
                "aweb",
                (
                    naapp.NavLink("aweb.ai", "https://aweb.ai"),
                    naapp.NavLink("awid", "https://awid.ai"),
                ),
            ),
        ),
        footer_bottom="secrets is a Native Agentic App on the aweb.ai hub. awid is the identity authority.",
        header_actions=(naapp.NavLink("Console", console_origin.rstrip("/") + "/"),),
        source_url="https://github.com/awebai/aweb/tree/main/naapp/secrets",
        og_image="/og-card.png",
    )


def _start_steps(
    public_origin: str, console_origin: str, manifest: dict[str, Any]
) -> tuple[naapp.NumberedStep, ...]:
    verb = shlex.quote(manifest["app"]["id"])
    console = escape(console_origin.rstrip("/") + "/", quote=True)
    return (
        naapp.NumberedStep(
            "Install secrets on your team",
            "Add the app to your aweb team and connect its audit hook to logs. Open secrets' "
            f'<a href="{console}">own console</a> to complete owner setup and enroll a passkey.',
            f"aw plugin install {shlex.quote(public_origin.rstrip('/'))}",
        ),
        naapp.NumberedStep(
            "Connect 1Password",
            f'In the <a href="{console}">console</a>, connect a read-only service account for a dedicated vault. '
            "Choose the item and field by reference; credential values stay stored in 1Password.",
        ),
        naapp.NumberedStep(
            "Grant an agent or a role permission",
            "Define a named operation or a pinned runner job, choose its policy, and grant it "
            "to an agent or an app-local role. Confirm the change with your owner passkey. "
            "Set <code>approve_only</code> when each use needs an enrolled approver's passkey.",
        ),
        naapp.NumberedStep(
            "Use it from MCP or aw",
            "Ask for the operation or runner job through the team's exposed MCP tools or the "
            "<code>aw secrets</code> commands. Both use the same grants and policies. Follow "
            "the approval request when required, then inspect the result and its audit record.",
            f"aw {verb} describe --secret EXAMPLE_REF\n"
            f"aw {verb} request --secret EXAMPLE_REF --request_id example-1 "
            "--operation OPERATION_ID --params '{}'",
        ),
    )


def render_landing_page(
    *, public_origin: str, console_origin: str, manifest: dict[str, Any] | None = None
) -> str:
    manifest = MANIFEST if manifest is None else manifest
    site = _site(
        public_origin=public_origin,
        console_origin=console_origin,
        title="secrets — controlled credential use for teams of agents",
        description=(
            "Let your agent team use credentials under grants, policies and passkey "
            "approvals. Broker HTTP calls or run pinned jobs, with each use attributed "
            "and recorded."
        ),
    )
    steps = naapp.render_numbered_steps(_start_steps(public_origin, console_origin, manifest))
    return naapp.page(
        site,
        f"""
    <section class="hero-center">
      <div class="wrap">
        <h1>Where teams of agents share credentials under control</h1>
        <p class="lede">Give an agent permission to use a credential for a task. Keep the value out of its tools and conversation.</p>
        <div class="cta-row">
          <a class="btn primary btn--lg" href="#use">Get started</a>
          <a class="btn secondary btn--lg" href="/llms.txt">Read llms.txt</a>
        </div>
        <p class="lede">With 1Password, the credential stays stored in your team's own vault. secrets reads it only to carry out an authorized use; it keeps no stored copy.</p>
        <figure class="hero-card">
          <p class="prose-intro">Agent team → Grant + policy → Passkey when required → HTTP operation / Pinned runner job</p>
          <figcaption class="prose-outro">Permission to act, with every use attributed and recorded.</figcaption>
        </figure>
      </div>
    </section>
    <section class="section section--tint">
      <div class="wrap">
        <div class="section-head">
          <h2>Share what a credential can do</h2>
          <p>An agent may need to deploy a service, call an API or query a database. It needs permission for that work. secrets gives it a bounded way to ask.</p>
        </div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Use without read-back</h3><p>No secrets interface returns a value to an agent, an owner or a service operator. There is no get-value or export operation.</p></article>
          <article class="card"><h3>Your vault, your custody</h3><p>Connect a read-only 1Password service account scoped to a dedicated vault. Manage and replace the credentials in 1Password. A native store sealed with KMS is also available.</p></article>
          <article class="card"><h3>A clear trust boundary</h3><p>secrets handles plaintext during dispatch. Operators able to run code as the service could read it, and 1Password's existing vault access still applies. This is controlled use, not zero-knowledge custody.</p></article>
        </div>
      </div>
    </section>
    <section class="section" id="use">
      <div class="wrap">
        <div class="section-head"><h2>Connect a vault. Grant a task. Let the team work.</h2>
          <p>First, install a supported version of aw and connect your team using the <a href="https://aweb.ai/docs/cli-tutorial/">getting-started guide</a>.</p>
        </div>
        {steps}
        <p class="prose-outro">Read the <a href="/reference">API reference</a> for commands and parameters, <a href="/llms.txt">llms.txt</a> for agent instructions, and <a href="/skills/">skills</a> for task workflows.</p>
      </div>
    </section>
    <section class="section section--tint">
      <div class="wrap">
        <div class="section-head"><h2>Two ways to use a secret</h2></div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>The broker makes the HTTP call</h3><p>An agent requests an allowed action. secrets checks its identity, grant and policy, obtains approval when required, then makes the HTTPS call with the credential. The agent receives a bounded result with output filtering and redaction.</p></article>
          <article class="card"><h3>The runner carries out a pinned job</h3><p>A registered process on your team's machine receives a credential for one authorized job. The credential goes to the job process, not the model. Jobs and parameters are defined in advance; agents cannot supply arbitrary commands. Use a dedicated OS user or container outside the agents' write access. The runner host is trusted with the credential.</p></article>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="wrap">
        <div class="section-head"><h2>Decide who can do what</h2></div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Grants to an agent or a role</h3><p>Share a secret's permitted uses with one verified agent or an app-local role. A team membership or an exposed tool alone does not grant use.</p></article>
          <article class="card"><h3>Named operations and policies</h3><p>Bound the action and its parameters, allowed destinations, rate and time window. Sensitive secrets require named operations.</p></article>
          <article class="card"><h3>approve_only with a passkey</h3><p>An enrolled approver reviews the exact request and confirms it with a passkey on secrets' own origin. The approval is bound to that request and consumed at most once.</p></article>
        </div>
      </div>
    </section>
    <section class="section section--tint">
      <div class="wrap">
        <div class="section-head"><h2>Stop access and see what happened</h2></div>
        <div class="card-grid card-grid--auto">
          <article class="card"><h3>Revoke narrowly, or stop the installation</h3><p>Remove an agent's grant or role assignment, revoke a role's grant, disable a secret, or use the installation kill switch. Narrowing access needs no passkey. It stops affected uses before dispatch; it cannot undo a call already sent or recall a credential already delivered to a runner.</p></article>
          <article class="card"><h3>Every use attributed, with records delivered to logs</h3><p>secrets records the requester, action, policy, approval where required, and outcome. It durably queues signed audit events before dispatch and delivers them to your team's logs app. Use is refused without an active audit target or when every active target's delivery backlog exceeds the allowed age. Audit events carry metadata, not credential values.</p></article>
        </div>
      </div>
    </section>
    <section class="section" id="engineers">
      <div class="wrap">
        <div class="section-head"><h2>A bounded action and an attributable record</h2></div>
        <div class="prose">
          <p>Each brokered use or runner job requires a verified member principal with a matching grant under a recorded policy. <code>approve_only</code> binds an enrolled approver's passkey decision to the frozen request. Intent and outcome are recorded, with audit events durably queued before dispatch.</p>
          <p>These guarantees depend on secrets being the credential's sole path to agents and on its service, vault, identity and runner trust boundaries. Redaction does not prove confidentiality: a result may contain something derived from a credential. A passkey proves an enrolled authenticator. An upstream effect may be uncertain; secrets records that uncertainty instead of treating it as success.</p>
        </div>
      </div>
    </section>
    <section class="section section--tint">
      <div class="wrap"><div class="section-head"><h2>Give your team permission for the work.</h2></div>
        <div class="cta-row"><a class="btn primary btn--lg" href="#use">Get started</a><a class="btn secondary btn--lg" href="/reference">API reference</a></div>
      </div>
    </section>
""",
    )


def render_reference_page(
    *, public_origin: str, console_origin: str, manifest: dict[str, Any] | None = None
) -> str:
    manifest = MANIFEST if manifest is None else manifest
    return naapp.render_reference(
        manifest,
        _site(
            public_origin=public_origin,
            console_origin=console_origin,
            title="secrets — API reference",
            description="Credential operations from the canonical app manifest. Team identity, grants, policy and invocation contexts apply.",
        ),
        verb=manifest["app"]["id"],
        copy=naapp.ReferenceCopy(
            rejects_subject="secrets",
            team_heading="Credential operations — team identity, grants and invocation contexts",
            envelope_path_example="/v1/secrets/example/requests",
        ),
    )


def llms_txt(
    *, public_origin: str, console_origin: str, manifest: dict[str, Any] | None = None
) -> str:
    manifest = MANIFEST if manifest is None else manifest
    origin = public_origin.rstrip("/")
    verb = manifest["app"]["id"]
    contexts = "\n".join(
        f"- {tool['name']}: {', '.join(tool.get('invocation_contexts', ['agent']))}"
        for tool in manifest["tools"]
    )
    hooks = "\n".join(
        f"- {entry['hook']}" for entry in manifest.get("hooks", {}).get("productions", [])
    )
    skills = "\n".join(f"- {origin}/skills/{name}/SKILL.md" for name in SKILLS.names())
    return f"""# secrets — controlled credential use for teams of agents

secrets brokers HTTPS calls and pinned runner jobs under grants, policy and
passkey approvals. No tool accepts or returns credential values. 1Password
values stay stored in the team's vault; secrets reads them during dispatch.
The service and runner host are trusted with plaintext. Not zero-knowledge.

Origin: {origin}
Console: {console_origin.rstrip("/")}/
Manifest: {origin}/aweb-app.json
Reference: {origin}/reference

## Getting started

First, install a supported version of aw and connect your team using the
getting-started guide: https://aweb.ai/docs/cli-tutorial/

Install from the origin: aw plugin install {shlex.quote(origin)}
Complete owner/passkey setup, connect 1Password, configure grants and activate
the audit hook to logs. Owners confirm widening changes on secrets' own console.
Never send a credential value through aw, MCP or a model conversation.

## Authentication

{naapp.llms.auth_section(manifest, origin)}

The verified principal still needs a matching secrets grant and policy.
Invocation contexts below are enforced; surface-only tools are not agent tools.
Exposing a tool through MCP grants nothing. approve_only requires an enrolled
approver's passkey over the frozen request on secrets' own origin.

## Operations

{naapp.llms.cert_operations(manifest, verb)}

## Invocation contexts

{contexts}

## Audit hook productions

{hooks}

Audit events are durably enqueued before dispatch and delivered to logs. They
contain metadata, never values. An unavailable audit target or stalled delivery
to every active target refuses new uses; enqueue is not proof of delivery.

## Skills

{skills}

## Boundaries

- Every use requires a verified principal, matching grant and recorded policy.
- A runner executes a pinned job, never a command the agent supplies. Isolate
  its OS user/container and config from agents. The job process has credentials.
- Revoke grants or disable the installation to stop affected future dispatch.
  This cannot undo upstream effects or recall credentials already released.
- Preserve request_id and the exact request on retries; outcome_unknown needs
  reconciliation. Never treat an uncertain effect as a successful one.
- Redaction is not a confidentiality proof. Results can contain credential
  derivatives. A passkey proves an enrolled authenticator, not a natural person.
- The guarantee covers only use through secrets, as the sole credential path.
"""


def mount_public_surfaces(
    api: FastAPI,
    *,
    runtime: NaappRuntime,
    health_checks: Mapping[str, HealthCheck],
    console_origin: str,
) -> None:
    """Mount on the public API app, replacing its manifest/health mounts.

    Composition supplies its complete check mapping (runtime checks plus KMS).
    It also supplies the actual console origin, whose root owns setup/sign-in.
    Do not mount this on the passkey console, whose origin and CSP are separate.
    """
    from aweb_naapp.runtime.app import mount_naapp_routes

    origin = runtime.settings.public_origin
    manifest = json.loads(runtime.manifest_bytes)

    async def landing() -> str:
        return render_landing_page(
            public_origin=origin, console_origin=console_origin, manifest=manifest
        )

    mount_naapp_routes(
        api,
        runtime=runtime,
        skills=SKILLS,
        landing=landing,
        reference_html=render_reference_page(
            public_origin=origin, console_origin=console_origin, manifest=manifest
        ),
        llms_txt=llms_txt(public_origin=origin, console_origin=console_origin, manifest=manifest),
        fonts_dir=_PACKAGE / "fonts",
        og_card_png=(_PACKAGE / "og-card.png").read_bytes(),
        health_checks=health_checks,
    )
