# Root to UID 1000 path audit

The dispatcher creates the account before transferring inputs. `Executor.upload`
owns every root upload and immediately applies its explicit owner/mode. Neither
source permissions nor the SSH daemon's umask determine admission.

| Path | Owner | Mode / rule | Consumer |
|---|---|---|---|
| `/opt/vm-gate`, `/var/log/vm-gate` | gateuser:gateuser | 0750 | Root setup; UID1000 traversal and log writes |
| `operator/` and module files | root:root | directories0755, files0644 after extraction | UID1000 Python imports; root sampler |
| `source.json`, `expected-host.json` | gateuser:gateuser | 0600 | UID0 negative control and UID1000 host verification |
| `launch.sh` | gateuser:gateuser | 0700 | UID1000 bash; uploaded through the same function before verification |
| `source.bundle`, `operator.tar.gz`, `ledger-before.tsv`, `ledger-logs-before.tar.gz` | root:root | 0600 | Root verification, fetch and extraction only |
| `origin/`, `source/` | gateuser:gateuser recursively | Git creates them under explicit umask022; tracked executable bits preserved | UID1000 Git reads/fetches, exact clean source |
| Configured ledger parent and `gate-locks/` | gateuser:gateuser | 0700 | UID1000 ledger lock/read/write |
| Configured ledger | gateuser:gateuser | installed0600 | UID1000 source gate |
| Configured `gate-logs/` and retained log files | gateuser:gateuser recursively | owner read/write, directory traversal; no group/other access | UID1000 reuse and append |
| Gate output, identity, start/end/exit and source-after files | gateuser:gateuser | source launch redirections, inherited private operator umask | UID1000 writes; root collection reads |
| Root sampler log, PID and memory samples | root:root | root SSH umask controls files; gate never needs to modify them | Root sampler and collector only |
| Root evidence archive, ledger-after and copied log directory | root:root | private collection files; only root reads for download | Local operator receives under private state root |
| Snapshot tool plan and new manifest uploads | root:root | 0600, same upload function | Root installer and manifest install |
| Installed snapshot manifest | root:root | explicit0644 | UID1000 verification after restoration |
| Gate-owned `/tmp` fixtures and runner volumes | source gate's users | determined by the tested source; not repaired by dispatcher | Source cleanup and root evidence collector |

Local keys, summaries, transferred archives and state remain in the private
operator directory under umask077. No local SSH private key is uploaded.
Snapshot restored-host preparation uses the same transfer/ownership path.

`acceptance/linux_launch.py` runs the actual prepare → root refusal → UID1000
host verification → launch → exit receipt → evidence collection using a Linux
container transport. Inputs begin root-owned0600. It first loads the observed
pre-fix Executor at ae79d4e92 and requires its source.json PermissionError, then
runs the corrected path. Git, Python, runuser, file permissions and collection
are real; Go/uv/Node version commands and the provider/SSH connection are fixture
boundaries. It neither allocates a VM nor claims to test cloud networking.
