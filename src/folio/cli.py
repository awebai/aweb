from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import subprocess
import sys
import webbrowser
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import uvicorn

DEFAULT_ORIGIN = "https://folio.aweb.ai"
IMAGE_CONTENT_TYPES = {
    ".gif": "image/gif",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
VIDEO_CONTENT_TYPES = {
    ".mov": "video/quicktime",
    ".mp4": "video/mp4",
    ".qt": "video/quicktime",
    ".webm": "video/webm",
}


class CLIError(Exception):
    pass


def _origin(value: str | None) -> str:
    return (value or os.environ.get("FOLIO_ORIGIN") or DEFAULT_ORIGIN).rstrip("/")


def _json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"))


def _run(args: list[str]) -> int:
    return subprocess.run(args).returncode


def _aw_request(
    method: str,
    path: str,
    *,
    origin: str,
    body: dict[str, Any] | None = None,
    body_file: Path | None = None,
) -> int:
    args = [
        "aw",
        "id",
        "request",
        method,
        f"{origin}{path}",
        "--team-auth",
        "--raw",
    ]
    if body is not None:
        args.extend(["--body", _json_dumps(body)])
    if body_file is not None:
        args.extend(["--body-file", str(body_file)])
    return _run(args)


def _aw_request_json(method: str, path: str, *, origin: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    args = [
        "aw",
        "id",
        "request",
        method,
        f"{origin}{path}",
        "--team-auth",
        "--raw",
    ]
    if body is not None:
        args.extend(["--body", _json_dumps(body)])
    completed = subprocess.run(args, text=True, capture_output=True)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    if completed.returncode != 0:
        raise CLIError(f"aw id request failed with exit code {completed.returncode}")
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CLIError("aw id request did not return JSON") from exc
    if not isinstance(parsed, dict):
        raise CLIError("aw id request returned non-object JSON")
    return parsed


def _read_text_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _read_bytes_base64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def _content_type(path: Path, override: str | None = None) -> str:
    if override:
        return override
    suffix = path.suffix.lower()
    if suffix in IMAGE_CONTENT_TYPES:
        return IMAGE_CONTENT_TYPES[suffix]
    if suffix in VIDEO_CONTENT_TYPES:
        return VIDEO_CONTENT_TYPES[suffix]
    guessed, _encoding = mimetypes.guess_type(path.name)
    if guessed:
        return guessed
    raise CLIError(f"Could not infer content type for {path}; pass --content-type")


def _parse_ttl(value: str) -> int:
    text = value.strip().lower()
    if not text:
        raise argparse.ArgumentTypeError("TTL must not be empty")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text[-1] in units:
        number = text[:-1]
        multiplier = units[text[-1]]
    else:
        number = text
        multiplier = 1
    try:
        amount = int(number)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("TTL must be seconds or use s/m/h/d suffix") from exc
    if amount < 1:
        raise argparse.ArgumentTypeError("TTL must be positive")
    return amount * multiplier


def _open_url(url: str) -> None:
    webbrowser.open(url)


def _upload_video_bytes(upload_url: str, path: Path, content_type: str) -> None:
    with path.open("rb") as file_obj:
        response = httpx.post(
            upload_url,
            files={"file": (path.name, file_obj, content_type)},
            timeout=300.0,
        )
    if response.status_code >= 400:
        raise CLIError(f"video upload failed with HTTP {response.status_code}: {response.text}")


def _cmd_create(args: argparse.Namespace) -> int:
    body = _read_text_file(args.body_file) if args.body_file else ""
    payload = {"slug": args.slug, "title": args.title, "body": body}
    return _aw_request("POST", "/v1/documents", origin=args.origin, body=payload)


def _cmd_version(args: argparse.Namespace) -> int:
    return _aw_request(
        "POST",
        f"/v1/documents/{args.slug}/versions",
        origin=args.origin,
        body_file=Path(args.body_file),
    )


def _cmd_upload(args: argparse.Namespace) -> int:
    path = Path(args.file)
    content_type = _content_type(path, args.content_type)
    if content_type.startswith("image/"):
        payload = {"content_type": content_type, "data_base64": _read_bytes_base64(path)}
        return _aw_request("POST", "/v1/assets", origin=args.origin, body=payload)
    if content_type.startswith("video/"):
        video_payload: dict[str, Any] = {"content_type": content_type, "filename": path.name}
        if args.max_duration is not None:
            video_payload["max_duration_seconds"] = args.max_duration
        response = _aw_request_json(
            "POST",
            "/v1/assets/video/direct-upload",
            origin=args.origin,
            body=video_payload,
        )
        upload_url = response.get("upload_url")
        if not isinstance(upload_url, str) or not upload_url:
            raise CLIError("video direct-upload response missing upload_url")
        _upload_video_bytes(upload_url, path, content_type)
        print(_json_dumps(response))
        return 0
    raise CLIError(f"Unsupported upload content type: {content_type}")


def _cmd_show(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {"slug": args.slug}
    if args.version is not None:
        payload["version"] = args.version
    if args.ttl is not None:
        payload["ttl_seconds"] = args.ttl
    response = _aw_request_json("POST", "/v1/present", origin=args.origin, body=payload)
    print(_json_dumps(response))
    url = response.get("url")
    if args.open and isinstance(url, str):
        _open_url(url)
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    return _aw_request("POST", f"/v1/present/{args.token}/revoke", origin=args.origin)


def _cmd_theme_get(args: argparse.Namespace) -> int:
    return _aw_request("GET", "/v1/theme", origin=args.origin)


def _load_theme_tokens(path: str | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CLIError("--tokens-file must contain a JSON object")
    tokens = payload.get("tokens", payload)
    if not isinstance(tokens, dict):
        raise CLIError("theme tokens must be a JSON object")
    result: dict[str, dict[str, str]] = {}
    for group, values in tokens.items():
        if not isinstance(group, str) or not isinstance(values, dict):
            continue
        result[group] = {str(key): str(value) for key, value in values.items()}
    return result


def _cmd_theme_set(args: argparse.Namespace) -> int:
    tokens = _load_theme_tokens(args.tokens_file)
    colors = tokens.setdefault("colors", {})
    fonts = tokens.setdefault("fonts", {})
    for key in ("background", "surface", "text", "muted", "border", "accent"):
        value = getattr(args, key)
        if value is not None:
            colors[key] = value
    if args.body_font is not None:
        fonts["body"] = args.body_font
    if args.heading_font is not None:
        fonts["heading"] = args.heading_font
    if not colors:
        tokens.pop("colors", None)
    if not fonts:
        tokens.pop("fonts", None)

    payload: dict[str, Any] = {"tokens": tokens}
    if args.header is not None:
        payload["header"] = args.header
    if args.footer is not None:
        payload["footer"] = args.footer
    if args.clear_logo:
        payload["clear_logo"] = True
    return _aw_request("PUT", "/v1/theme", origin=args.origin, body=payload)


def _cmd_theme_logo(args: argparse.Namespace) -> int:
    path = Path(args.file)
    content_type = _content_type(path, args.content_type)
    if content_type not in set(IMAGE_CONTENT_TYPES.values()):
        raise CLIError("Theme logo must be image/png, image/jpeg, image/gif, or image/webp")
    payload = {"logo": {"content_type": content_type, "data_base64": _read_bytes_base64(path)}}
    return _aw_request("PUT", "/v1/theme", origin=args.origin, body=payload)


def _cmd_serve(_args: argparse.Namespace) -> int:
    uvicorn.run("folio.api:app", host="127.0.0.1", port=8765, reload=False)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aw folio",
        description="First-class folio verbs backed by aw id request --team-auth.",
    )
    parser.add_argument(
        "--origin",
        default=None,
        help="folio origin (default: FOLIO_ORIGIN or https://folio.aweb.ai)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    create = subcommands.add_parser("create", help="create a document")
    create.add_argument("slug")
    create.add_argument("--title", required=True)
    create.add_argument("--body-file")
    create.set_defaults(func=_cmd_create)

    version = subcommands.add_parser("version", help="append a document version")
    version.add_argument("slug")
    version.add_argument("--body-file", required=True)
    version.set_defaults(func=_cmd_version)

    upload = subcommands.add_parser("upload", help="upload an image or create a video direct upload")
    upload.add_argument("file")
    upload.add_argument("--content-type")
    upload.add_argument("--max-duration", type=int)
    upload.set_defaults(func=_cmd_upload)

    show = subcommands.add_parser("show", help="mint and print a presentation link")
    show.add_argument("slug")
    show.add_argument("--version", type=int)
    show.add_argument("--ttl", type=_parse_ttl)
    show.add_argument("--open", action="store_true")
    show.set_defaults(func=_cmd_show)

    revoke = subcommands.add_parser("revoke", help="revoke a presentation token")
    revoke.add_argument("token")
    revoke.set_defaults(func=_cmd_revoke)

    theme = subcommands.add_parser("theme", help="read or update the team presentation theme")
    theme_subcommands = theme.add_subparsers(dest="theme_command", required=True)
    theme_get = theme_subcommands.add_parser("get", help="read the current theme")
    theme_get.set_defaults(func=_cmd_theme_get)

    theme_set = theme_subcommands.add_parser("set", help="set theme tokens/header/footer")
    theme_set.add_argument("--tokens-file")
    for color in ("background", "surface", "text", "muted", "border", "accent"):
        theme_set.add_argument(f"--{color}")
    theme_set.add_argument("--body-font", choices=["system", "serif", "mono"])
    theme_set.add_argument("--heading-font", choices=["system", "serif", "mono"])
    theme_set.add_argument("--header")
    theme_set.add_argument("--footer")
    theme_set.add_argument("--clear-logo", action="store_true")
    theme_set.set_defaults(func=_cmd_theme_set)

    theme_logo = theme_subcommands.add_parser("logo", help="set the theme logo from a raster file")
    theme_logo.add_argument("file")
    theme_logo.add_argument("--content-type")
    theme_logo.set_defaults(func=_cmd_theme_logo)

    serve = subcommands.add_parser("serve", help="run the local development API server")
    serve.set_defaults(func=_cmd_serve)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    parsed = parser.parse_args(argv)
    parsed.origin = _origin(parsed.origin)
    try:
        return parsed.func(parsed)
    except CLIError as exc:
        print(f"folio: {exc}", file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
