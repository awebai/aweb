# Local whole-suite admission

The local server/registry runner, the three-lane user-path runner and Cloud's
local backend runner share one machine-wide semaphore. Admission precedes
installation, image preparation and service creation; release follows cleanup.
Canonical gates do not use this limiter.

## 1. Shared files and capacity

All runners use `/private/tmp/aweb-local-suite-slots/slot-N.lock`, numbered from
zero. `AWEB_LOCAL_SUITE_SLOTS` sets the positive capacity, default **3**. Use the
same value for every seat on the host, and change it only when no whole-suite
run is active. The directory is explicitly mode 0777 and
files mode 0666, independent of umask, so seats share the same inodes. The path
is fixed; it does not vary with checkout, account, repository or `TMPDIR`.

Never delete or replace these files while runners may exist. File existence and
metadata are not occupancy: only the kernel lock determines whether a slot is
held. Descriptors use `O_CLOEXEC` and are not inherited by suite subprocesses.

## 2. Lock and owner protocol

Each runner opens the persistent files and tries `fcntl.flock(LOCK_EX | LOCK_NB)`
in order. If all are occupied, it prints the holder descriptions and repeats the
nonblocking scan every two seconds, reporting current holders once per minute.
It takes any freed slot, never exceeds the configured capacity, and starts no
services while waiting.

Under the acquired lock, the runner truncates and writes one JSON line with
`pid`, `repo` (`aweb` or `ac`), `source_sha`, `label` (`server`, `registry`,
`user-paths` or `backend`) and `started_utc`. Optional `owner` identifies the
seat. These fields describe the holder for waiting output; they do not grant a
slot or authorize killing the holder. A partially written record is displayed
as metadata being published, while its lock remains occupied.

The wrapper retains the lock through normal, failed and interrupted cleanup.
Closing the descriptor releases it on every process exit, including SIGKILL;
SIGKILL still cannot execute application cleanup. Interrupted waiters exit
without starting a project. Do not unlink the file when releasing the lock.

## 3. Focused feedback

Explicit pytest paths/node IDs, `-k`, `-m` and `--deselect` selections bypass
admission. This includes selections in `LOCAL_PYTEST_ARGS` or `PYTEST_ADDOPTS`.
Root `tests` or `.` and options that only change reporting, verbosity or timing
still run whole suites and take a slot. Unknown options are treated
conservatively so an option's value cannot masquerade as a test path.

`make test-user-paths-local` always runs all three declared lanes, so it holds
one slot for the complete invocation. An unrelated pytest environment variable
does not narrow those lanes or bypass their admission.

The protocol, rather than shared Python code, is the cross-repository contract.
The aweb owner is `scripts/local_suite_slots.py`. Real-process controls in
`scripts/test_local_suite_slots.py` exercise contention and exit handling with
service boundaries held, without invoking Docker or claiming service coverage.
