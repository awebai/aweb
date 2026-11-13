"""Real private file checks for the optional public-key-to-custody manifest."""

import base64
import json
from types import SimpleNamespace

import pytest
from awid.did import did_from_public_key, generate_keypair
from aweb_naapp.runtime.protected_signer import SignerRefused

from aweb.protected_signing.host import load_custodies
from aweb.protected_signing.profile import ProtectedServiceProfile
from tests.test_protected_service_profile import FIXTURE


@pytest.fixture
def slots(tmp_path):
    fields = json.loads(FIXTURE.read_bytes())
    paths, seeds = {}, []
    first = fields["bindings"][0]
    second = {**first, "scope": {**first["scope"], "authority": {
        "kind": "human_identity", "id": first["scope"]["human"]["id"], "domain": first["scope"]["human"]["domain"]}}}
    fields["bindings"] = [first, second]
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    for index, binding in enumerate(fields["bindings"]):
        seed, public = generate_keypair()
        seeds.append(seed)
        key = did_from_public_key(public)
        binding["authority_key_did"] = key
        path = directory / (str(index)+".key")
        path.write_text(seed.hex()+"\n")
        path.chmod(0o400)
        paths[key] = str(path)
    profile = ProtectedServiceProfile.from_json(json.dumps(fields).encode())
    manifest = tmp_path / "controllers.json"
    manifest.write_text(json.dumps(paths))
    member, member_public = generate_keypair()
    member_file = tmp_path / "member.pem"
    member_file.write_bytes(b"-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(member) + b"\n-----END ED25519 PRIVATE KEY-----\n")
    member_file.chmod(0o400)
    members = tmp_path / "members.json"
    members.write_text(json.dumps({first["scope"]["authority"]["id"]: str(member_file)}))
    from pathlib import Path

    settings = SimpleNamespace(controller_keys_file=manifest, controller_key_file=Path(next(iter(paths.values()))),
        member_keys_file=members, worker_uids=[65534], member_public=did_from_public_key(member_public))
    return settings, profile, paths, member_file, seeds


def test_every_provisioned_authority_uses_its_matching_private_file(slots):
    settings, profile, _, _, _ = slots
    selected, members, custody = load_custodies(settings, profile=profile, scope=profile.bindings[0].scope.model_dump(mode="json"))
    assert selected == profile.bindings[0]
    assert set(members) == {selected.context().authority_id}
    assert [key.team_key_did for _, key in custody] == [binding.authority_key_did for binding in profile.bindings]
    assert [key.authority_kind for _, key in custody] == ["team_controller", "human_identity"]


@pytest.mark.parametrize("case", ["missing", "extra", "relative", "selected_mismatch", "swapped", "symlink", "member_is_human_key", "member_is_namespace_key"])
def test_unprovisioned_or_unsafe_authority_never_reaches_the_database(slots, case):
    from pathlib import Path

    settings, profile, paths, member_file, seeds = slots
    keys = list(paths)
    if case == "missing":
        paths.pop(keys[1])
    elif case == "extra":
        paths["not-in-profile"] = paths[keys[0]]
    elif case == "relative":
        paths[keys[1]] = "relative.key"
    elif case == "selected_mismatch":
        settings.controller_key_file = Path(paths[keys[1]])
    elif case == "swapped":
        paths[keys[1]] = paths[keys[0]]
    elif case == "symlink":
        alias = settings.controller_keys_file.parent / "alias.key"
        alias.symlink_to(paths[keys[1]])
        paths[keys[1]] = str(alias)
    elif case == "member_is_namespace_key":
        fields = profile.fields()
        fields["namespace_authorities"][0]["controller_did"] = settings.member_public
        profile = ProtectedServiceProfile.from_json(json.dumps(fields).encode())
    else:
        member_file.chmod(0o600)
        member_file.write_bytes(b"-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(seeds[1]) + b"\n-----END ED25519 PRIVATE KEY-----\n")
    settings.controller_keys_file.write_text(json.dumps(paths))
    with pytest.raises(SignerRefused):
        load_custodies(settings, profile=profile, scope=profile.bindings[0].scope.model_dump(mode="json"))
