from __future__ import annotations

import json
from pathlib import Path

from folio import cli


class RunRecorder:
    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, args: list[str]) -> int:
        self.calls.append(args)
        return self.returncode


def test_create_wraps_aw_team_auth_request(monkeypatch, tmp_path) -> None:
    body = tmp_path / "pitch.md"
    body.write_text("# Pitch\n", encoding="utf-8")
    recorder = RunRecorder()
    monkeypatch.setattr(cli, "_run", recorder)

    rc = cli.run(["--origin", "https://folio.example", "create", "pitch", "--title", "Pitch", "--body-file", str(body)])

    assert rc == 0
    assert recorder.calls == [
        [
            "aw",
            "id",
            "request",
            "POST",
            "https://folio.example/v1/documents",
            "--team-auth",
            "--raw",
            "--body",
            json.dumps({"slug": "pitch", "title": "Pitch", "body": "# Pitch\n"}, separators=(",", ":")),
        ]
    ]


def test_version_sends_raw_body_file(monkeypatch, tmp_path) -> None:
    body = tmp_path / "pitch-v2.md"
    body.write_text("# Pitch v2\n", encoding="utf-8")
    recorder = RunRecorder()
    monkeypatch.setattr(cli, "_run", recorder)

    rc = cli.run(["version", "pitch", "--body-file", str(body)])

    assert rc == 0
    assert recorder.calls == [
        [
            "aw",
            "id",
            "request",
            "POST",
            "https://folio.aweb.ai/v1/documents/pitch/versions",
            "--team-auth",
            "--raw",
            "--body-file",
            str(body),
        ]
    ]


def test_show_parses_ttl_and_can_open_returned_url(monkeypatch, capsys) -> None:
    opened: list[str] = []

    def fake_request_json(method: str, path: str, *, origin: str, body: dict | None = None) -> dict:
        assert method == "POST"
        assert path == "/v1/present"
        assert origin == "https://folio.aweb.ai"
        assert body == {"slug": "pitch", "ttl_seconds": 86400}
        return {"url": "https://folio.aweb.ai/present/token"}

    monkeypatch.setattr(cli, "_aw_request_json", fake_request_json)
    monkeypatch.setattr(cli, "_open_url", lambda url: opened.append(url))

    rc = cli.run(["show", "pitch", "--ttl", "1d", "--open"])

    assert rc == 0
    assert opened == ["https://folio.aweb.ai/present/token"]
    assert "https://folio.aweb.ai/present/token" in capsys.readouterr().out


def test_revoke_calls_revoke_endpoint(monkeypatch) -> None:
    recorder = RunRecorder()
    monkeypatch.setattr(cli, "_run", recorder)

    rc = cli.run(["revoke", "tok_123"])

    assert rc == 0
    assert recorder.calls[0][:5] == [
        "aw",
        "id",
        "request",
        "POST",
        "https://folio.aweb.ai/v1/present/tok_123/revoke",
    ]


def test_upload_image_builds_base64_asset_payload(monkeypatch, tmp_path) -> None:
    image = tmp_path / "logo.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nbytes")
    captured: dict[str, object] = {}

    def fake_request(method: str, path: str, *, origin: str, body: dict | None = None, body_file: Path | None = None) -> int:
        captured.update(method=method, path=path, origin=origin, body=body, body_file=body_file)
        return 0

    monkeypatch.setattr(cli, "_aw_request", fake_request)

    rc = cli.run(["upload", str(image)])

    assert rc == 0
    assert captured["method"] == "POST"
    assert captured["path"] == "/v1/assets"
    assert captured["body"] == {"content_type": "image/png", "data_base64": "iVBORw0KGgpieXRlcw=="}


def test_upload_video_requests_direct_upload_and_uploads_bytes(monkeypatch, tmp_path, capsys) -> None:
    video = tmp_path / "demo.mp4"
    video.write_bytes(b"fake video")
    captured: dict[str, object] = {}
    uploaded: list[tuple[str, Path, str]] = []

    def fake_request_json(method: str, path: str, *, origin: str, body: dict | None = None) -> dict:
        captured.update(method=method, path=path, body=body)
        return {"asset_id": "asset-1", "upload_url": "https://upload.example/direct"}

    monkeypatch.setattr(cli, "_aw_request_json", fake_request_json)
    monkeypatch.setattr(cli, "_upload_video_bytes", lambda url, path, content_type: uploaded.append((url, path, content_type)))

    rc = cli.run(["upload", str(video), "--max-duration", "300"])

    assert rc == 0
    assert captured["method"] == "POST"
    assert captured["path"] == "/v1/assets/video/direct-upload"
    assert captured["body"] == {"content_type": "video/mp4", "filename": "demo.mp4", "max_duration_seconds": 300}
    assert uploaded == [("https://upload.example/direct", video, "video/mp4")]
    assert "asset-1" in capsys.readouterr().out


def test_theme_set_and_logo_build_payloads(monkeypatch, tmp_path) -> None:
    logo = tmp_path / "logo.webp"
    logo.write_bytes(b"RIFFxxxxWEBP")
    calls: list[dict[str, object]] = []

    def fake_request(method: str, path: str, *, origin: str, body: dict | None = None, body_file: Path | None = None) -> int:
        calls.append({"method": method, "path": path, "body": body, "body_file": body_file})
        return 0

    monkeypatch.setattr(cli, "_aw_request", fake_request)

    assert cli.run(["theme", "set", "--background", "#001122", "--body-font", "serif", "--header", "Team memo"]) == 0
    assert calls[-1] == {
        "method": "PUT",
        "path": "/v1/theme",
        "body": {"tokens": {"colors": {"background": "#001122"}, "fonts": {"body": "serif"}}, "header": "Team memo"},
        "body_file": None,
    }

    assert cli.run(["theme", "logo", str(logo)]) == 0
    assert calls[-1]["method"] == "PUT"
    assert calls[-1]["path"] == "/v1/theme"
    assert calls[-1]["body"] == {"logo": {"content_type": "image/webp", "data_base64": "UklGRnh4eHhXRUJQ"}}
