"""Public docs use the composed manifest and the shared naapp surface."""

import copy
import html as html_module
import json
import re
import shlex
from pathlib import Path

import aweb_naapp as naapp
import httpx
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.health import CheckResult
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME, SecretsService
from aweb_secrets.config import SecretsSettings
from aweb_secrets.manifest import MANIFEST, MANIFEST_PATH
from aweb_secrets.surfaces import (
    SKILLS,
    llms_txt,
    mount_public_surfaces,
    render_landing_page,
    render_reference_page,
)

ORIGIN = "https://secrets.aweb.ai"


def test_landing_has_shared_chrome_steps_and_working_document_links() -> None:
    html = render_landing_page(public_origin=ORIGIN)
    assert len(re.findall(r"<h1[ >]", html)) == 1
    assert '<header class="site-header">' in html
    assert f"/css/aweb.{naapp.CSS_SHA256[:12]}.css" in html
    assert 'id="use"' in html
    assert '<ol class="gs-steps" role="list">' in html
    assert len(re.findall(r'<li class="gs-step">', html)) == 4
    for href in ("#use", "/reference", "/llms.txt", "/skills/", "/aweb-app.json"):
        assert f'href="{href}"' in html
    assert "<style" not in html


def test_reference_and_llms_follow_the_supplied_manifest_not_a_tool_list() -> None:
    manifest = copy.deepcopy(MANIFEST)
    manifest["app"]["id"] = "self-hosted-secrets"
    manifest["tools"].append(
        {
            "name": "probe",
            "method": "GET",
            "path": "/v1/probe/{ref}",
            "description": "A new declared operation.",
            "params": [{"name": "ref", "in": "path"}],
            "input_schema": {"type": "object", "properties": {"ref": {"type": "string"}}},
            "invocation_contexts": ["agent", "surface"],
        }
    )
    text = llms_txt(public_origin=ORIGIN, manifest=manifest)
    html = render_reference_page(public_origin=ORIGIN, manifest=manifest)
    assert html.count('<article class="ref-op"') == len(manifest["tools"])
    for tool in manifest["tools"]:
        assert naapp.llms.operation_block(tool, manifest["app"]["id"]) in text
        assert f'id="op-{tool["name"]}"' in html
        assert tool["path"] in text
        assert tool["path"] in html
    assert "aw self-hosted-secrets probe" in html
    for production in manifest["hooks"]["productions"]:
        assert production["hook"] in text
    assert SKILLS.names()
    for name in SKILLS.names():
        assert f"/skills/{name}/SKILL.md" in text


def test_getting_started_commands_fit_the_composed_manifest() -> None:
    manifest = copy.deepcopy(MANIFEST)
    manifest["app"]["id"] = "self-hosted-secrets"
    html = render_landing_page(public_origin=ORIGIN, manifest=manifest)
    tools = {tool["name"]: tool for tool in manifest["tools"]}
    commands = [
        shlex.split(line)
        for block in re.findall(r"<pre>(.*?)</pre>", html, re.S)
        for line in html_module.unescape(block).splitlines()
    ]
    assert commands[0] == ["aw", "plugin", "install", ORIGIN]
    for command in commands[1:]:
        assert command[:2] == ["aw", manifest["app"]["id"]]
        tool = tools[command[2]]
        flags = {token.removeprefix("--") for token in command[3::2]}
        assert flags <= {param["name"] for param in tool["params"]}
        required, _ = naapp.manifest.tool_params(tool)
        assert set(required) <= flags


def _runtime(tmp_path: Path) -> NaappRuntime:
    keys = {}
    for index, entry in enumerate(MANIFEST["app_keys"]):
        path = tmp_path / f"key-{index}"
        path.write_text(SigningKey.generate().encode().hex())
        path.chmod(0o600)
        keys[entry["kid"]] = path
    settings = SecretsSettings(
        _env_file=None,
        public_origin=ORIGIN,
        console_origin="https://console.secrets.test",
        app_key_files=keys,
    )
    return NaappRuntime(
        settings,
        module_name=MODULE_NAME,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
    )


async def test_public_routes_mount_only_on_api_and_keep_manifest_assets_and_health(
    tmp_path,
) -> None:
    runtime = _runtime(tmp_path)
    api, console = FastAPI(), FastAPI()

    async def unavailable_kms() -> CheckResult:
        return CheckResult(ok=False)

    checks = {**runtime.health_checks(), "kms": unavailable_kms}
    mount_public_surfaces(api, runtime=runtime, health_checks=checks)
    service = SecretsService(runtime, api, console)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service), base_url=ORIGIN
    ) as client:
        for path, content_type in (
            ("/", "text/html"),
            ("/reference", "text/html"),
            ("/llms.txt", "text/plain"),
            ("/skills/", "text/plain"),
        ):
            response = await client.get(path)
            assert response.status_code == 200, path
            assert response.headers["content-type"].startswith(content_type)
            assert "set-cookie" not in response.headers
            assert (await client.get("https://console.secrets.test" + path)).status_code == 404
        served = await client.get("/aweb-app.json")
        assert served.content == runtime.manifest_bytes
        assert (await client.get("/llms.txt")).text == llms_txt(
            public_origin=ORIGIN, manifest=json.loads(served.content)
        )
        css = await client.get(f"/css/aweb.{naapp.CSS_SHA256[:12]}.css")
        assert css.text == naapp.aweb_css()
        assert (await client.get("/fonts/BerkeleyMono-Regular.woff2")).status_code == 200
        card = await client.get("/og-card.png")
        assert card.content.startswith(b"\x89PNG\r\n\x1a\n")
        for name in SKILLS.names():
            response = await client.get(f"/skills/{name}/SKILL.md")
            assert response.status_code == 200
            assert response.text == SKILLS.read(name)
        assert (await client.get("/skills/not-a-skill/SKILL.md")).status_code == 404
        health = await client.get("/ready")
        assert health.status_code == 503
        assert set(health.json()["checks"]) == {"database", "outbox", "kms"}
        assert health.json()["checks"]["kms"] == {"ok": False}
