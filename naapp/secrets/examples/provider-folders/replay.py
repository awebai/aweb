"""Replay one seat's outbox into its OneDrive app folder, as a pinned runner job.

Usage: python3 -I replay.py --config <operator config>

The operator configuration fixes every input. The access token is read from
the file the runner fills; this program never obtains, refreshes or stores
one. The outcome is one JSON object on stdout and an exit code from ExitCode.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# -I leaves the script's directory off sys.path. The package modules come
# first; the vendored dependency tree comes after the standard library, so no
# file in it can shadow a standard module.
sys.path.insert(0, str(HERE))
sys.path.append(str(HERE / "vendor"))

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import ssl  # noqa: E402
import stat  # noqa: E402
from dataclasses import asdict, dataclass  # noqa: E402
from enum import IntEnum  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402

import httpx  # noqa: E402

from onedrive import (  # noqa: E402
    Destination,
    GraphAppFolder,
    ProviderDenied,
    ProviderRejected,
    ProviderUnavailable,
)
from publisher import (  # noqa: E402
    SEAT,
    DirectoryOutbox,
    Outcome,
    PublishConfig,
    Publisher,
    Reason,
    Receipt,
    Refused,
)

CONFIG_MAX_BYTES = 65536
TOKEN_MAX_BYTES = 16384
OUTPUT_MIN_BYTES = 512
# RFC 6750 b64token: the only characters a bearer token may carry.
BEARER_TOKEN = re.compile(rb"[A-Za-z0-9\-._~+/]+=*")
CONFIG_FIELDS = frozenset(
    {
        "seat",
        "state_dir",
        "outbox",
        "max_bytes",
        "extensions",
        "destination",
        "graph_origin",
        "token_file",
        "ca_bundle",
        "output_max_bytes",
    }
)


class ExitCode(IntEnum):
    """The run's outcome. 1 and 2 stay Python's crash and argparse's usage codes."""

    OK = 0
    REFUSED = 3
    UNCERTAIN = 4
    RUN_REFUSED = 5
    OUTPUT_TOO_LARGE = 6


class RunRefused(Exception):
    """The run was refused as a whole; no further job was attempted."""

    def __init__(self, reason: Reason):
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class RunConfig:
    seat: str
    state_dir: Path
    outbox: Path
    max_bytes: int
    extensions: frozenset[str]
    destination: Destination
    graph_origin: str
    token_file: Path
    ca_bundle: Path | None
    output_max_bytes: int


def load_config(path: Path) -> RunConfig:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(CONFIG_MAX_BYTES + 1)
        body = json.loads(raw)
    except (OSError, ValueError):
        raise RunRefused(Reason.CONFIG_INVALID) from None
    if len(raw) > CONFIG_MAX_BYTES or not isinstance(body, dict) or set(body) != CONFIG_FIELDS:
        raise RunRefused(Reason.CONFIG_INVALID)
    destination = body["destination"]
    extensions = body["extensions"]
    ca_bundle = body["ca_bundle"]
    if not (
        isinstance(body["seat"], str)
        and SEAT.fullmatch(body["seat"])
        and _positive(body["max_bytes"])
        and _positive(body["output_max_bytes"])
        and body["output_max_bytes"] >= OUTPUT_MIN_BYTES
        and isinstance(extensions, list)
        and all(isinstance(value, str) and value.isalnum() for value in extensions)
        and isinstance(destination, dict)
        and set(destination) == {"drive_id", "folder_id"}
        and all(isinstance(value, str) and value for value in destination.values())
        and _https_origin(body["graph_origin"])
        and all(_absolute(body[key]) for key in ("state_dir", "outbox", "token_file"))
        and (ca_bundle is None or _absolute(ca_bundle))
    ):
        raise RunRefused(Reason.CONFIG_INVALID)
    return RunConfig(
        seat=body["seat"],
        state_dir=Path(body["state_dir"]),
        outbox=Path(body["outbox"]),
        max_bytes=body["max_bytes"],
        extensions=frozenset(extensions),
        destination=Destination(**destination),
        graph_origin=body["graph_origin"],
        token_file=Path(body["token_file"]),
        ca_bundle=None if ca_bundle is None else Path(ca_bundle),
        output_max_bytes=body["output_max_bytes"],
    )


def read_token(path: Path) -> str:
    """Read the access token the runner placed; any doubt refuses the run."""
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise RunRefused(Reason.TOKEN_UNAVAILABLE) from None
    try:
        if not stat.S_ISREG(os.fstat(handle).st_mode):
            raise RunRefused(Reason.TOKEN_UNAVAILABLE)
        raw = os.read(handle, TOKEN_MAX_BYTES + 1)
    finally:
        os.close(handle)
    token = raw.removesuffix(b"\n")
    if len(raw) > TOKEN_MAX_BYTES or not BEARER_TOKEN.fullmatch(token):
        raise RunRefused(Reason.TOKEN_UNAVAILABLE)
    return token.decode("ascii")


def run(config: RunConfig, client: httpx.Client) -> tuple[ExitCode, bytes]:
    """Replay the outbox; return the exit code and the bounded JSON report."""
    try:
        token = read_token(config.token_file)
        folder = GraphAppFolder(client, token=lambda: token, base=f"{config.graph_origin}/v1.0")
        publisher = Publisher(
            PublishConfig(config.seat, config.state_dir, config.max_bytes, config.extensions),
            DirectoryOutbox(config.outbox),
            folder,
        )
        if _destination(folder) != config.destination:
            raise RunRefused(Reason.DESTINATION_MISMATCH)
        try:
            receipts = publisher.replay()
        except Refused as refusal:
            raise RunRefused(refusal.reason) from None
    except RunRefused as refusal:
        return ExitCode.RUN_REFUSED, _render("run_refused", refusal.reason, [])
    code = _exit_code(receipts)
    output = _render(code.name.lower(), None, receipts)
    if len(output) > config.output_max_bytes:
        counts: dict[str, int] = {}
        for receipt in receipts:
            counts[receipt.outcome] = counts.get(receipt.outcome, 0) + 1
        summary = {"v": 1, "outcome": "output_too_large", "reason": None, "counts": counts}
        return ExitCode.OUTPUT_TOO_LARGE, json.dumps(summary, sort_keys=True).encode()
    return code, output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="replay.py")
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        config = load_config(arguments.config)
        verify = _tls_context(config.ca_bundle)
    except RunRefused as refusal:
        code, output = ExitCode.RUN_REFUSED, _render("run_refused", refusal.reason, [])
    else:
        # trust_env=False: no proxy, certificate or netrc setting from the
        # environment can redirect the bearer away from the configured origin.
        with httpx.Client(verify=verify, trust_env=False) as client:
            code, output = run(config, client)
    sys.stdout.buffer.write(output + b"\n")
    return code


def _tls_context(ca_bundle: Path | None) -> ssl.SSLContext:
    try:
        return ssl.create_default_context(cafile=None if ca_bundle is None else str(ca_bundle))
    except (OSError, ssl.SSLError):
        raise RunRefused(Reason.CONFIG_INVALID) from None


def _destination(folder: GraphAppFolder) -> Destination:
    try:
        return folder.destination()
    except ProviderDenied:
        raise RunRefused(Reason.PROVIDER_DENIED) from None
    except ProviderRejected:
        raise RunRefused(Reason.PROVIDER_REJECTED) from None
    except ProviderUnavailable:
        raise RunRefused(Reason.PROVIDER_UNAVAILABLE) from None


def _exit_code(receipts: list[Receipt]) -> ExitCode:
    outcomes = {receipt.outcome for receipt in receipts}
    if Outcome.UNCERTAIN in outcomes:
        return ExitCode.UNCERTAIN
    if Outcome.REFUSED in outcomes:
        return ExitCode.REFUSED
    return ExitCode.OK


def _render(outcome: str, reason: Reason | None, receipts: list[Receipt]) -> bytes:
    body = {
        "v": 1,
        "outcome": outcome,
        "reason": reason,
        "receipts": [asdict(receipt) for receipt in receipts],
    }
    return json.dumps(body, sort_keys=True).encode()


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _absolute(value: object) -> bool:
    return isinstance(value, str) and Path(value).is_absolute()


def _https_origin(value: object) -> bool:
    """A bare https origin: scheme, host and optional port, nothing else."""
    if not isinstance(value, str):
        return False
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and (port is None or port > 0)
        and parts.username is None
        and parts.password is None
        and not parts.path
        and not parts.query
        and not parts.fragment
        and value == f"https://{parts.netloc}"
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
