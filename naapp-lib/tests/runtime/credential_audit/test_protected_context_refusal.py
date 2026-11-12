"""The installed-app recorder must not reinterpret a protected authority scope."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.passkeys import CredentialChangeRefused, PasskeyInstallationContext
from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext


class DB:
    @asynccontextmanager
    async def transaction(self):
        yield object()


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [True, False])
async def test_credential_change_preparation_distinguishes_the_two_scope_kinds(protected):
    selected = []
    app = PasskeyInstallationContext("demo", "demo:example.org", "installation", 1)
    context = (
        ProtectedKeyContext(
            "signer",
            "team_controller",
            "demo:example.org",
            "example.org",
            "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
            "example.org",
            1,
        )
        if protected
        else app
    )

    async def contexts(scope, *, tx):
        return context

    async def permit(team_id):
        selected.append(team_id)
        return SimpleNamespace(admitted=app)

    async def view(team_id):
        return None

    # Preparation test only. No fake evidence is admitted to a writer/effect.
    owner = SimpleNamespace(
        db=DB(),
        _contexts=contexts,
        fence=SimpleNamespace(permit=permit, for_installation=lambda admitted: object()),
        _view=view,
    )
    if protected:
        with pytest.raises(CredentialChangeRefused) as refused:
            await CredentialAudit.prepare_credential_change(owner, "selected-scope")
        assert refused.value.reason == "completion_authority_unavailable"
        assert selected == []
    else:
        prepared = await CredentialAudit.prepare_credential_change(owner, "selected-scope")
        assert prepared.scope == "selected-scope"
        assert selected == ["demo:example.org"]
