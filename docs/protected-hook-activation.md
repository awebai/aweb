# Protected hook-binding activation

`hook-binding.activate/default` is a team-controller `live_floor` act in the
existing human-assurance catalog. The protected service holds the controller
key. The requesting identity sends one typed binding subject; an eligible
configured human logs in and separately approves that exact request with a
passkey. A controller signature alone does not assert that activation applied.

```sh
aw hooks bindings logs
aw hooks activate logs <binding-id> --protected-profile signer.json --approver did:aw:<human>
aw hooks resume <operation-id> --protected-profile signer.json
```

Activation fetches the installed manifest from its origin at its pinned digest
and compares the entire binding with that manifest. The existing closed
`aweb.owner-act/1` subject names the binding ID, installation ID and generation,
app, origin, manifest digest, catalog/version, hook, and either the registration
method/path/tool/scopes or the production's reads. It approves one binding at a
time; neither an app name nor a previous generation's approval activates a new
set of bindings. Install and update continue to create pending bindings.

The CLI's activation route requires the public profile and named approver. It
has no local controller-key fallback or `--yes` signing route. The shared
prepare/approve/execute engine freezes the exact subject and digest. The CLI
verifies the returned signature, current profile key pin, audience and exact
subject using the existing owner-act verifier before sending it to the
coordination server's `/v1/apps/hook-bindings/<id>/activate` endpoint.

The saved request survives signing and any unconfirmed delivery. Resume sends
the same retained request and delivers the same signed act, with its original
nonce and expiry. The server acknowledges a repeated activation only after
fresh current-key verification, under the locked current installation and
binding, when both the activation hash and the committed nonce receipt match
the exact signed bytes. It creates no second effect or audit event. Another act,
a missing nonce receipt, a changed generation, an ended binding, an expired act
or a rotated-out key never acknowledges the old activation as current.

The CLI removes its saved request only after the activation response names the
same team's exact binding and reports it active. The binding's existing
60-second `active_from` delay remains in effect. Browser/native execution and
joined deployment acceptance are separate from source and pure transport tests.
The remaining hook revocation command retains its existing route until its
catalog CLI integration is completed.
