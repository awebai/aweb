# Windows identity persistence (aweb-actp)

Status: proposal for Athena's contract ruling and Juan's explicit approval;
no implementation is authorized by this document. Goal 1, “Make aweb.ai a
significant business”: restore reliable Windows identity operations and CI.

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
directory and calls `Sync` (`awconfig/id_issuance_store.go:175–190`), while
`human_record_test.go` sets `HOME` without Windows' `USERPROFILE`. The former
is a product defect, introduced by `fb961bddc`; parent-directory sync and the
POSIX-only directory-mode admission check came with `0be3e9eee`. The test
isolation defect came with `f41961e4b`. See task aweb-actp and Windows run
[41767381811](https://github.com/awebai/aweb/actions/runs/41767381811).

## Candidate publication primitive and unresolved guarantee

Propose a Windows-only path using a flushed staging file and
`MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
Keep staging and destination in the same directory/volume; never enable
copy-across-volume or delayed-until-reboot fallback. File contents are written
completely and `FlushFileBuffers` succeeds on the writable staging handle
before close and publication. Microsoft documents the handle's write-access
requirement and flushing buffered file data in
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

For a missing directory, create a private, uniquely named sibling, then publish
it with `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` without replacement. Establish
missing ancestors in order from an existing parent, not by an unflushed
`MkdirAll` followed by flushing only the leaf. A collision revalidates the
existing directory under the existing transaction lock; it never replaces it.
Microsoft explicitly demonstrates this flag for same-drive directory moves in
[Moving Directories](https://learn.microsoft.com/en-us/windows/win32/fileio/moving-directories).
Keep all final paths and record encodings unchanged.

**This is a candidate, not a demonstrated equivalence to POSIX fsync+rename.**
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
describes write-through completion on disk, but its explicit flush guarantee
then discusses copy-and-delete moves. It does not spell out crash atomicity of
same-volume replacement or persistence of every newly created ancestor. The
directory example establishes supported API usage, not a crash theorem.
Athena must rule on that gap before this can be an implementation design: either
identify sufficient platform authority for this sequence and its supported
filesystem scope, or require a different persistence design. A green test must
not silently turn the candidate into the accepted durability contract. No new
filesystem restriction or weaker guarantee is adopted here.

Do not substitute a successful file flush for name publication, suppress a
failed directory sync, or choose `ReplaceFileW` on the assumption that it has a
working write-through flag: Microsoft explicitly marks
[`REPLACEFILE_WRITE_THROUGH` unsupported](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
Volume flushing requires administrative privileges per the FlushFileBuffers
reference; it is not a transparent remedy for an ordinary CLI user.

## Private directories on Windows

`Mode().Perm()==0700` is a Unix check, not a Windows privacy proof. Propose
explicit Windows security descriptors for newly created record directories
and staging files: current user's SID as owner, a protected non-null DACL,
full control for that SID and LocalSystem, and no grants to other principals.
Set it at creation, before writing any record, with appropriate child
inheritance. Administrators exercising OS privilege remain outside this
ordinary-user isolation boundary, as root does on Unix.

Microsoft documents creation-time descriptors and inspection via
`GetSecurityInfo` in
[File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
A default descriptor inherits parent ACLs; renaming does not assign a fresh
default descriptor. [SE_DACL_PROTECTED](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control)
prevents inherited ACEs from changing the DACL. The target filesystem must
support persistent ACLs for creation-time security to take effect
([CreateDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)).

For existing store directories, inspect ownership and effective grants on the
opened object, retain rejection of redirected/non-directory objects, and accept
only access equivalent to the approved private policy. A broad/null DACL or
unverifiable ACL is an explicit refusal with a repair explanation, not an
automatic ACL rewrite. Inspect record files too: Windows parent-directory
privacy alone does not establish child-file privacy. Do not change the user's
profile ACL or another identity's records. Athena must approve this ACL policy
and its compatibility treatment for existing stores; it is not an already
accepted narrowing of Windows support.

## Unix invariants and proof

The Unix implementation of temp-file creation, chmod, write, file sync, close,
rename, directory sync and directory admission stays byte-identical when moved
behind build tags. No refactor of that path is needed. Final filenames,
JSON/YAML bytes, canonical certificates, signing inputs, existing lock scope,
refusal semantics and frozen vectors remain unchanged on every platform.
Tests set both HOME and USERPROFILE to disposable homes; Unix mode assertions
remain, while Windows checks actual ACLs instead of skipping privacy coverage.

After approval, native Windows tests must exercise creation, replacement,
reopening/retry, private versus broad ACLs, and failures at publication. A
regression test must fail on the current code. Process termination around
write/flush/publication must show that no response escapes before the chosen
persistence barrier succeeds and retries use the exact recorded response.
Failures are surfaced with their
real Win32 cause; success cannot be manufactured by ignoring one.

Those tests establish behavior on the tested filesystem and OS; process kill
does not simulate power loss or discard kernel/device caches. Controlled
crash/power-cut trials can falsify the design, not prove every storage stack.
Durability depends on a documented OS/filesystem contract and a device honoring
flushes. In particular, native CI cannot settle the MoveFileExW guarantee gap
above. Juan's approval and Athena's ACK must precede implementation and be
recorded in its commit; unresolved durability means no implementation ACK.

Design discipline: accepted guarantees are not weakened to match an
implementation; see accepted knowledge
`aweb/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md@c375d3925b1f`.
