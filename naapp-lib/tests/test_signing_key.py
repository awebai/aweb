from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from aweb_naapp.signing_key import SigningKeyError, parse_signing_key_hex, read_signing_key_file

SRC = Path(__file__).resolve().parents[1] / "src"


def _key_file(tmp_path: Path, text: str, *, mode: int = 0o600) -> Path:
    path = tmp_path / "app.key"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_a_key_file_holds_the_seed_as_hex(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    key = read_signing_key_file(_key_file(tmp_path, seed + "\n"))
    assert bytes(key) == bytes.fromhex(seed)


@pytest.mark.parametrize("text", ["{seed}", "{seed}\n", "{upper}", "{upper}\n"])
def test_the_format_is_64_hex_with_an_optional_newline(text: str) -> None:
    seed = secrets.token_hex(32)
    key = parse_signing_key_hex(text.format(seed=seed, upper=seed.upper()))
    assert bytes(key) == bytes.fromhex(seed)


@pytest.mark.parametrize(
    "text",
    ["{seed}\n\n", " {seed}", "{seed}\r\n", "{short}", "{seed}00", "{nothex}", "{spaced}", ""],
)
def test_any_other_format_is_refused_without_echoing_it(text: str) -> None:
    seed = secrets.token_hex(32)
    content = text.format(
        seed=seed, short=seed[:62], nothex="zz" + seed[2:], spaced=seed[:40] + " " + seed[40:]
    )
    with pytest.raises(SigningKeyError) as refused:
        parse_signing_key_hex(content)
    for fragment in (seed[:40], seed[40:], seed[2:]):
        assert fragment not in str(refused.value)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o444])
def test_read_permissions_are_left_to_the_platform(tmp_path: Path, mode: int) -> None:
    seed = secrets.token_hex(32)
    assert bytes(read_signing_key_file(_key_file(tmp_path, seed, mode=mode))) == bytes.fromhex(seed)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_a_group_or_world_writable_file_is_refused(tmp_path: Path, mode: int) -> None:
    path = _key_file(tmp_path, secrets.token_hex(32), mode=mode)
    with pytest.raises(SigningKeyError, match=str(path)):
        read_signing_key_file(path)


def test_a_key_file_reached_through_a_symlink_is_read(tmp_path: Path) -> None:
    # Mounted secrets are commonly symlinks into a versioned directory.
    seed = secrets.token_hex(32)
    link = tmp_path / "linked.key"
    link.symlink_to(_key_file(tmp_path, seed))
    assert bytes(read_signing_key_file(link)) == bytes.fromhex(seed)


def test_a_path_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "app.key"
    directory.mkdir(mode=0o700)
    with pytest.raises(SigningKeyError, match=str(directory)):
        read_signing_key_file(directory)


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    missing = tmp_path / "absent.key"
    with pytest.raises(SigningKeyError, match=str(missing)):
        read_signing_key_file(missing)


def test_a_malformed_file_is_refused_without_echoing_it(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    path = _key_file(tmp_path, seed[:62])
    with pytest.raises(SigningKeyError, match=str(path)) as refused:
        read_signing_key_file(path)
    assert seed[:62] not in str(refused.value)


def test_the_loader_imports_with_the_standard_library_and_pynacl_alone() -> None:
    heavy = ("awid", "fastapi", "httpx", "pgdbm", "pydantic", "starlette", "aweb_naapp.runtime")
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import aweb_naapp.signing_key\n"
        f"print(','.join(m for m in {heavy!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""
