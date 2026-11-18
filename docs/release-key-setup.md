# Release signing: proof, active and successor devices

**The PIV PIN is separate from the PIN you already use for FIDO2 or OpenPGP.**
These steps address only PIV; they leave FIDO2, OpenPGP and the existing OpenPGP
key and touch policy alone. There is no device or applet reset in this procedure.

Before provisioning the active or successor device, the release maintainer and
a second reviewer must approve these commands and accept the third-device proof.
This procedure authenticates the publisher of executable releases.

## Mac tools and signing format

Use YubiKey Manager **5.9.2** (Homebrew formula `ykman`). It supplies both key
provisioning and the signing adapter through its supported `script` command;
no `yubico-piv-tool`, PKCS#11 setup or separate Python packages are needed.
[Yubico documents scripting with the bundled libraries and dependencies](https://developers.yubico.com/yubikey-manager/Scripting.html).
There is no built-in `ykman piv sign` command. Our reviewed adapter calls
`PivSession.sign(..., key_type=KEY_TYPE.ED25519, hash_algorithm=None)`;
[Yubico 5.9.2 source](https://github.com/Yubico/yubikey-manager/blob/5.9.2/yubikit/piv.py#L546-L548)
passes Ed25519 message bytes unchanged, and its
[sign method](https://github.com/Yubico/yubikey-manager/blob/5.9.2/yubikit/piv.py#L1135-L1161)
sends them to the private-key operation. This is raw Ed25519 over the statement,
with no OpenPGP, SSH or FIDO envelope. This source evidence still needs the device proof below.

Install once on the Mac, without a YubiKey connected:

```sh
brew install ykman openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
ykman --version
openssl version
```

These commands change Mac files and this terminal's PATH only; Homebrew packages
can be uninstalled and PATH restored. Reviewed formula versions on 2026-11-18:
[ykman 5.9.2](https://formulae.brew.sh/formula/ykman) and
[openssl@3 3.5.9](https://formulae.brew.sh/formula/openssl@3).
Homebrew does not promise a frozen version for these install names. If the
reported versions differ, have a second reviewer read that tool version before device
writes. Use the repository's existing Go and Python 3 setup for the proof.

From the reviewed repository root, prepare local paths:

```sh
umask 077
AW_RELEASE_TOOLS="$PWD/cli/go"
AW_RELEASE_KEY_FILES="$HOME/aw-release-public-keys"
mkdir -p "$AW_RELEASE_KEY_FILES"
```

This changes only this terminal and a local directory, which can be removed when
its public records are preserved elsewhere. Keep each device's new PIV PIN, PUK
and management key in your own recovery storage, outside this repository and
terminal logs. Choose distinct eight-digit PIV PIN and PUK values. Generate a
random 32-byte management secret (64 hexadecimal characters) in your password
manager. Do not pass any of these secrets as command arguments or environment
variables. All credential prompts below are interactive and hidden.

The signed statement is ASCII, exactly four LF-terminated lines, at most 256
bytes:

```text
aw-release-statement-v1
version=0.0.0-rc.1
source_commit=<full lowercase source commit>
manifest_sha256=<SHA-256 of the exact manifest file bytes>
```

The metavariables illustrate the format; the tool writes actual values. No one
reformats the manifest after staging. The envelope stores the statement bytes
and raw signature as base64. Both verifiers check signature, manifest digest,
matching version/commit, and artifact digests, in that order.

## Device 1: proof only

Connect only the proof device. Its private key is disposable and is never a
production pin. The first command for this device is:

```sh
ykman info
```

Read-only. Record serial and firmware. **Stop for firmware below 5.7**: that
device cannot hold an Ed25519 PIV release key. Repeat this check independently
for every device; one device's firmware establishes nothing about the others.
The [versioned SDK enforces this minimum](https://github.com/Yubico/yubikey-manager/blob/5.9.2/yubikit/piv.py#L630-L638).

Select the displayed serial and inspect PIV:

```sh
printf 'Proof device serial: '
read -r AW_PROOF_SERIAL
ykman --device "$AW_PROOF_SERIAL" piv info
ykman --device "$AW_PROOF_SERIAL" piv keys info 9c
```

The prompt changes a terminal variable; inspection is read-only. Slot 9c must
report no key. A key can exist without a certificate: do not infer emptiness
from the certificate list. If any key metadata appears, or PIV credentials are
not defaults, stop and reconcile that device before proceeding. An empty slot's
inspection may exit with an error; that is expected only for the explicit
no-key result, not a connection or authorization error.

With the factory retry limits used here, three consecutive wrong PIV PIN tries
block the PIN; three wrong PUK tries separately block the PUK. A working PUK can
unblock the PIN. A blocked PUK cannot be unblocked, even with the management key.
A working PIN remains usable, but if the PIN is also blocked, recovery requires a
PIV applet reset. That destroys every PIV slot key, including a release key on
that device, and leaves FIDO2 and OpenPGP untouched. Stop for review after an
error rather than using up the remaining tries. This procedure changes no retry
limits and includes no reset command.
[Yubico explains these retry and recovery rules](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html#blocking).

Change all three PIV defaults before generating a signing key:

```sh
ykman --device "$AW_PROOF_SERIAL" piv access change-pin
ykman --device "$AW_PROOF_SERIAL" piv access change-puk
ykman --device "$AW_PROOF_SERIAL" piv access change-management-key --algorithm AES256 --touch
```

For `change-pin`, enter the current **PIV** default `123456`, then the new PIV PIN
twice. It replaces only PIV's PIN; it can be changed again with the current PIN,
or recovered with its PUK. For `change-puk`, enter default `12345678`, then the
new independent PUK twice. It replaces PIV's recovery code; changing it again
requires the current PUK. For `change-management-key`, press Return at the
current-key prompt to use the factory default, then paste the new 64-hex secret
at the hidden new-key prompts. It replaces PIV's administrative secret, selects
AES-256 and requires physical touch for administrative authentication. It can
be changed again with administrative authentication. Touch if prompted. This
uses a separately held management secret, not one stored behind the signing PIN.
[Yubico's versioned CLI source defines these prompts and operations](https://github.com/Yubico/yubikey-manager/blob/5.9.2/ykman/_cli/piv.py#L377-L602).

Now generate once and inspect/export the **public** half:

```sh
ykman --device "$AW_PROOF_SERIAL" piv keys generate --algorithm ED25519 --pin-policy ALWAYS --touch-policy ALWAYS 9c "$AW_RELEASE_KEY_FILES/proof-generated.pem"
ykman --device "$AW_PROOF_SERIAL" piv keys info 9c
ykman --device "$AW_PROOF_SERIAL" piv keys export --verify 9c "$AW_RELEASE_KEY_FILES/proof.pem"
cmp "$AW_RELEASE_KEY_FILES/proof-generated.pem" "$AW_RELEASE_KEY_FILES/proof.pem"
```

Generation creates the private key inside PIV slot 9c and writes only the public
key to the Mac. Enter the new management secret and touch as prompted. This is
**irreversible**: running generation again can destroy the old slot key. Its
private bytes cannot be exported or reconstructed. `ALWAYS` requires a fresh
PIV PIN verification and a physical touch for each signature, without a cached
signing window; those slot policies cannot be edited in place. Metadata must
say ED25519, generated on-device, PIN ALWAYS, touch ALWAYS. Inspection changes
nothing. Export `--verify` exercises a signature (new PIV PIN and touch), checks
that public and private halves match, and writes a public file; it does not
export or modify the private key. `cmp` is read-only and must succeed.
[The CLI reference distinguishes generation, metadata and verified public export](https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html#ykman-piv-keys-generate-options-slot-public-key).

Prepare the throwaway statement, sign it and run both production verifier owners:

```sh
AW_PROOF_DIR="$AW_RELEASE_KEY_FILES/proof-run"
python3 "$AW_RELEASE_TOOLS/release_signing_proof.py" prepare --directory "$AW_PROOF_DIR" --commit "$(git rev-parse HEAD)"
cat "$AW_PROOF_DIR/release-statement.txt"
ykman script -- "$AW_RELEASE_TOOLS/sign_release_statement.py" --serial "$AW_PROOF_SERIAL" --public-key "$AW_RELEASE_KEY_FILES/proof.pem" --statement "$AW_PROOF_DIR/release-statement.txt" --signature "$AW_PROOF_DIR/release-statement.rawsig"
python3 "$AW_RELEASE_TOOLS/release_signing_proof.py" verify --directory "$AW_PROOF_DIR" --public-key "$AW_RELEASE_KEY_FILES/proof.pem"
```

Preparation creates local throwaway artifact/manifest/statement files and refuses
an existing proof directory. The script checks serial, firmware, on-device origin,
slot policies and public key; displays the exact short statement; and asks for
`SIGN`, the PIV PIN and touch. It performs one PIV signature and writes its 64-byte
result; it does not provision or change a key. Successful PIN verification is
transient; an incorrect PIN consumes a retry, so stop on failure rather than
retrying guesses. Verification writes only local public evidence, runs the Go
owner, then the generated shell owner with an external **proof-only** pin; neither
changes production pins. It appends a newline to a separate manifest copy and
requires both verifiers to refuse it with the original statement/signature. It
never rewrites the staged original. Local proof files may be archived or deleted;
the signing operation itself cannot be undone, but publishes nothing.

Required result: Go accepts the original, Go refuses the tampered manifest,
shell accepts the original, shell refuses the tampered manifest with retry
guidance. Save these four PASS lines, the exact source SHA/tool versions, the
statement, signature, public key and both manifest files for the release maintainer
and a second reviewer.
Do not record secrets or enable traffic/debug logging. If any step fails, stop
and send the error for review; no active/successor provisioning or pin publication
follows a failed proof. Do not guess PINs, regenerate keys or change device
configuration to work around a refusal.

### After the proof

The proof device retains a disposable private key in PIV slot 9c and its PIV
PIN, PUK and management key are no longer defaults. It is not a blank spare.
After the release maintainer and a second reviewer accept the saved proof
material, the device owner may permanently remove only that proof key. Connect
only the proof device and check its serial against `AW_PROOF_SERIAL`, then run:

```sh
ykman --device "$AW_PROOF_SERIAL" piv keys delete 9c
```

This requires the proof device's management key at the hidden prompt and a
physical touch, because management-key authentication was configured with
`--touch`. It irreversibly deletes the private key in PIV slot 9c; there is no
undo. Saved signatures still verify with the exported public key. The command
does not restore PIV credentials to defaults, alter other slots, or affect FIDO2
or OpenPGP, so the device still is not a blank spare afterwards. Retain its
nondefault credentials if you intend to reuse its PIV applet.
[The versioned CLI source authenticates before deleting the selected key](https://github.com/Yubico/yubikey-manager/blob/5.9.2/ykman/_cli/piv.py#L948-L961).

## Device 2: active release key

Only after the proof is accepted, disconnect proof and connect only the active
device. The first command for this device is:

```sh
ykman info
```

Read-only; record its own serial/firmware and stop below 5.7. Then:

```sh
printf 'Active device serial: '
read -r AW_ACTIVE_SERIAL
ykman --device "$AW_ACTIVE_SERIAL" piv info
ykman --device "$AW_ACTIVE_SERIAL" piv keys info 9c
ykman --device "$AW_ACTIVE_SERIAL" piv access change-pin
ykman --device "$AW_ACTIVE_SERIAL" piv access change-puk
ykman --device "$AW_ACTIVE_SERIAL" piv access change-management-key --algorithm AES256 --touch
ykman --device "$AW_ACTIVE_SERIAL" piv keys generate --algorithm ED25519 --pin-policy ALWAYS --touch-policy ALWAYS 9c "$AW_RELEASE_KEY_FILES/active-generated.pem"
ykman --device "$AW_ACTIVE_SERIAL" piv keys info 9c
ykman --device "$AW_ACTIVE_SERIAL" piv keys export --verify 9c "$AW_RELEASE_KEY_FILES/active.pem"
cmp "$AW_RELEASE_KEY_FILES/active-generated.pem" "$AW_RELEASE_KEY_FILES/active.pem"
```

Apply the same stop conditions and hidden prompts as Device 1, with this device's
own distinct credentials. Run each line separately and inspect success before
the next. The two initial inspections are read-only and 9c must be empty. PIN,
PUK and management changes are credential changes recoverable as described above.
Generation is the irreversible creation of the **production** private key;
metadata is read-only; verified export signs a challenge and writes only public
bytes; `cmp` is read-only. Retain this device and credentials in your custody.
Exporting this public key does not authorize a pin change: hand `active.pem` to
the reviewed client-pin change after both production public keys exist.

For a real release, stage all artifacts once and create its manifest with
`release_manifest.py create` as documented in install-integrity.md. From that
staging directory, set `AW_RELEASE_STAGE` to its absolute path, then run:

```sh
python3 "$AW_RELEASE_TOOLS/release_manifest.py" statement --manifest "$AW_RELEASE_STAGE/release-manifest.json" --output "$AW_RELEASE_STAGE/release-statement.txt"
cat "$AW_RELEASE_STAGE/release-statement.txt"
ykman script -- "$AW_RELEASE_TOOLS/sign_release_statement.py" --serial "$AW_ACTIVE_SERIAL" --public-key "$AW_RELEASE_KEY_FILES/active.pem" --statement "$AW_RELEASE_STAGE/release-statement.txt" --signature "$AW_RELEASE_STAGE/release-statement.rawsig"
python3 "$AW_RELEASE_TOOLS/release_manifest.py" attach-signature --statement "$AW_RELEASE_STAGE/release-statement.txt" --raw-signature "$AW_RELEASE_STAGE/release-statement.rawsig" --key-id active --output "$AW_RELEASE_STAGE/release-manifest.sig"
```

The first and last commands only create local immutable files. The signer has
the same transient PIN/touch and detached-signature effects as the proof; no
persistent device configuration changes. Compare version, source commit and
manifest SHA-256 with the reviewed release before typing SIGN and touching.
Then use the documented local verification and two independent-host byte readback
before treating publication as complete. These commands do not publish anything.

## Device 3: successor release key

Disconnect active and connect only the successor device. Its first command is:

```sh
ykman info
```

Read-only; record its own serial/firmware and stop below 5.7. Then:

```sh
printf 'Successor device serial: '
read -r AW_SUCCESSOR_SERIAL
ykman --device "$AW_SUCCESSOR_SERIAL" piv info
ykman --device "$AW_SUCCESSOR_SERIAL" piv keys info 9c
ykman --device "$AW_SUCCESSOR_SERIAL" piv access change-pin
ykman --device "$AW_SUCCESSOR_SERIAL" piv access change-puk
ykman --device "$AW_SUCCESSOR_SERIAL" piv access change-management-key --algorithm AES256 --touch
ykman --device "$AW_SUCCESSOR_SERIAL" piv keys generate --algorithm ED25519 --pin-policy ALWAYS --touch-policy ALWAYS 9c "$AW_RELEASE_KEY_FILES/successor-generated.pem"
ykman --device "$AW_SUCCESSOR_SERIAL" piv keys info 9c
ykman --device "$AW_SUCCESSOR_SERIAL" piv keys export --verify 9c "$AW_RELEASE_KEY_FILES/successor.pem"
cmp "$AW_RELEASE_KEY_FILES/successor-generated.pem" "$AW_RELEASE_KEY_FILES/successor.pem"
```

Run each line separately, using this device's own credentials and the same empty
9c/default-PIV checks. Inspections and `cmp` are read-only. Credential changes
can be changed again under their current authority. Generation irreversibly
creates a distinct successor private key in this device; it is never copied
from active. Verified export signs a challenge and writes a public file only.
Keep the successor physically separate. Deliver `successor.pem` with `active.pem`
for review; the proof key is excluded from both production pins.

Installed clients pinned to active and successor can verify a release signed by
either. If active is lost, successor signs the client release that introduces a
new successor pin; older clients continue to trust that signature. If the only
usable pinned private key is lost (or both devices are lost), old clients cannot
authenticate a replacement key through this channel. They keep their installed
binary; recovery requires an explicitly authenticated out-of-band reinstall or
client update. No checksum-only bypass, invented replacement pin or silently
weakened verifier repairs that loss. The current missing-manifest warning stage
does not make an unpinned signature authenticated; later mandatory-manifest
clients refuse unsigned upgrades.
