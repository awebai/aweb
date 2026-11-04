# Windows identity persistence (aweb-actp)

Status: direction ACKed by Athena (ruling `b5dc2af9-4a2a-4293-94ab-074b962a6601`,
relayed in full by the coordinator in `e5f58a45-c3d5-4364-bf77-ba2c01a4ee85`).
Implementation awaits Juan's explicit approval; this document does not grant it.
Goal 1, “Make aweb.ai a significant business”: restore reliable Windows identity
operations and CI.

## Contract and scope

The local issuer retains custody and authorization; filesystem permissions do
not establish controller authority. This change concerns its on-disk records,
not hosted custody, membership, certificate bytes or verification rules. The
issuer must retain issuance provenance before releasing a certificate
([id-certificates.md](id-certificates.md), lines 416–428 and 1053–1054 at
`c375d3925`); the child still verifies the parent chain and signature before
atomic installation (lines 1059–1064). An I/O error must withhold the response,
including an error after publication; a retry recovers the existing exact
record rather than signing again (lines 963–969).

Current Windows failures have two causes: `syncDirectory` opens a read-only
directory and calls `Sync` (`cli/go/awconfig/id_issuance_store.go:175–190`), while
`human_record_test.go` sets `HOME` without Windows' `USERPROFILE`. The former
is a product defect, introduced by `fb961bddc`; parent-directory sync and the
POSIX-only directory-mode admission check came with `0be3e9eee`. The test
isolation defect came with `f41961e4b`. See task aweb-actp and Windows run
[41767381811](https://github.com/awebai/aweb/actions/runs/41767381811).

## Accepted Windows publication barrier

On a local NTFS or ReFS volume, write the complete staging file, successfully
call `FlushFileBuffers` on its writable handle, close it, then publish to a
same-directory target with
`MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
The response is released only after successful publication. Microsoft documents
writable-handle flushing in
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
and write-through move completion in
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
Do not enable cross-volume copying or delayed-until-reboot publication.

Athena accepts this as the Windows barrier under the same standard as Unix:
a documented OS contract and a device that honors flushes. It is not a claim
of crash atomicity on every storage stack. The previous proposal's request for
a stronger Windows crash guarantee is resolved by that ruling.

Create directories normally. The issuance directory remains an `os.Mkdir`
under the existing identity home (`cli/go/awconfig/id_issuance_store.go:48`).
On Windows, `syncDirectory` becomes a build-tagged no-op; the record's
write-through publication is the barrier. There is no sibling-directory
staging scheme or added ancestor-publication mechanism.

If an OS crash or power cut loses a directory or provenance entry, re-signing
refuses because provenance is missing; a submitted certificate cannot seed the
log ([id-certificates.md](id-certificates.md), lines 416–428). Athena's ruling
identifies recovery as a new invitation: this loss affects the child's
availability, not acceptance of a forged or backdated certificate. It does not
justify a stronger Windows persistence mechanism in this task.

Do not substitute `ReplaceFileW`: Microsoft marks
[`REPLACEFILE_WRITE_THROUGH` unsupported](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
Do not add volume flushing, which requires administrative privileges per the
FlushFileBuffers reference. Preserve all final paths and record encodings.

## Windows directory security baseline

Match the existing identity-home policy:
[`identity_home_owner_windows.go`](../cli/go/awconfig/identity_home_owner_windows.go),
lines 7–9, relies on Windows profile ACLs and performs no ACL inspection.
Directories are created normally and inherit their parent's ACLs; issuance
records remain within the identity home. Microsoft describes default inheritance
in [File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

The `Mode().Perm()==0700` admission check becomes Unix-only behind a build tag.
Go's synthetic Windows mode is not a privacy proof. Retain the existing
`Lstat`/`IsDir` redirect and non-directory refusal on both platforms
(`cli/go/awconfig/id_issuance_store.go:43–60`). No creation-time security
descriptors, ACL inspection, new ACL-based refusal of existing stores, or
record-file ACL checks are added.

Athena rejected the earlier strict DACL proposal because the identity home
already holds the signing key under the baseline ACL policy. A stricter
subdirectory policy would strand existing Windows users without protecting the
key beside it. Any future ACL hardening belongs to the identity home as a whole,
including that key, in a separate task with a named attack.

## Unix invariants and validation

The Unix implementation of temp-file creation, chmod, write, file sync, close,
rename, directory sync and directory admission stays byte-identical when moved
behind build tags. Final filenames, JSON/YAML bytes, canonical certificates,
signing inputs, existing lock scope, Unix refusal semantics and frozen vectors
remain unchanged. Tests set both HOME and USERPROFILE to disposable homes;
POSIX mode assertions remain Unix-only, matching the platform admission policy.

After approval, run the existing store tests on native Windows CI. Their RED
is run [41767381811](https://github.com/awebai/aweb/actions/runs/41767381811).
Cover create, replace and exact retry, and an ordinary injected publication
error that withholds the response unless existing coverage already proves it.
Errors retain their real Win32 cause. No process-kill or power-cut trials are
required for this fix.

Native tests establish behavior on the tested Windows filesystem and OS; they
do not prove power-loss behavior of every device. Durability carries the same
OS-contract/device-flush caveat as Unix. Athena's ruling and Juan's approval
must both be recorded in the implementation commit. Until Juan's approval is
relayed, only this documentation is authorized to change.

Design discipline: accepted guarantees change by explicit ruling; see
`aweb/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md@c375d3925b1f`.
