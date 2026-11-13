# Load ramp measurements

`collect.py` samples one team deployment's Compose project while the load
driver ramps seats. `summarise.py` turns each step into one table per service.
The driver is separate. The two share only the mark file.

Both need Python 3.11 or later with no packages, and the Docker CLI with access
to the deployment's daemon. Run them on the deployment's host so that the
marks, the samples and Docker's log timestamps share one clock.

## Marks

The driver appends one JSON object per line, with `t` in Unix seconds from the
host's clock:

```json
{"t": 1794542962.02, "event": "warmup_start", "seats": 10}
{"t": 1794542962.02, "event": "step_start", "seats": 20}
{"t": 1794542981.80, "event": "step_end", "seats": 20}
```

A step is the window from its `step_start` to the `step_end` with the same
seats. A step that is never ended is reported as open. It runs to the next
`step_start` or to the last sample. Warmup is not summarised.

## Collecting

```sh
python3 collect.py --project teamcompose --out samples.jsonl          # until SIGINT or SIGTERM
python3 collect.py --project teamcompose --out samples.jsonl --duration 600
```

Every 5 s (`--interval`), it appends one JSON line per sample. Every line has
`t` and `kind`:

| kind | from | what |
|---|---|---|
| `meta` | `docker info` | project, interval, host CPUs and memory, the service names used |
| `container` | `docker stats`, `docker inspect` | CPU %, memory and limit, network and block I/O (cumulative), PIDs, restarts, OOM kill, CPU limit |
| `postgres` | `psql` in the `postgres` and `registry-db` containers | `max_connections`, and per database: connections, active, idle in transaction, waiting on a lock, ungranted locks, longest lock wait, commits and rollbacks (cumulative), deadlocks. `statements` holds the top ten by time when `pg_stat_statements` is already loaded and installed |
| `redis` | aweb's Redis through the aweb container; `redis-cli` in `registry-redis` | clients, maxclients, blocked clients, memory and maxmemory, commands (cumulative), rejected connections, evictions |
| `log` | `docker logs` of every container | HTTP statuses from access lines; WARNING and higher levels from JSON, uvicorn and PostgreSQL lines; PostgreSQL errors by class (`too_many_clients`, `lock_timeout`, `statement_timeout`, `idle_in_transaction_timeout`, `deadlock`, `out_of_memory`, `other`). Counts are kept per whole second, together with each key's exact first time |
| `probe_error` | the collector | a probe that failed, and why. The next tick retries it |

Service names default to the team deployment's (`aweb`, `redis`, `postgres`,
`registry-db`, `registry-redis`). Override them with `--aweb-service`,
`--redis-service`, `--postgres-service`, `--registry-db-service` and
`--registry-redis-service`. A service that is absent is skipped. A deployment
whose PostgreSQL is not bundled has no `postgres` samples.

### What it never does

- It writes nothing to the deployment. Its SQL only selects. It enables no
  extension, resets no statistic or limiter, and changes no configuration.
- It holds no credential:
  - PostgreSQL is read as `postgres` over the container's local socket, which
    needs no password.
  - The registry's Redis has no password.
  - aweb's Redis password stays in the aweb container. A short script on the
    container's stdin reads the URL file aweb is given (`AWEB_REDIS_URL_FILE`,
    else `/run/secrets/aweb/redis-url`) with the image's own Python and redis
    client, and prints only counters, or an exception's class name.
- It writes no message text from logs, only counts and times.
- It keeps statement text only for SELECT, INSERT, UPDATE, DELETE and WITH
  statements, whose constants `pg_stat_statements` has already replaced with
  parameters. A utility statement's text is kept verbatim there, and
  `CREATE ROLE ... PASSWORD` is a utility statement.

### Cost

Each tick runs:

- `docker ps`, `docker stats --no-stream` and `docker inspect` once;
- one `docker logs` per container;
- one short `psql` connection per PostgreSQL container;
- one `docker exec` per Redis.

Its own statements appear in `statements`, and its connections in the counts,
as one connection.

## Summarising

```sh
python3 summarise.py --samples samples.jsonl --marks marks.jsonl              # every step, Markdown
python3 summarise.py --samples samples.jsonl --marks marks.jsonl --seats 40 --json
```

Each step gets six things:

- **Containers:** CPU mean and max, memory max, and network and block I/O over
  the step.
- **PostgreSQL**, per database: connection, lock and transaction-rate figures,
  plus the statements that took the most time in the step.
- **Redis:** clients, blocked clients, commands per second, memory, rejections
  and evictions.
- **HTTP**, per service: status counts, the time of the first 429 and of the
  first 5xx, and 429s and 5xx per minute of the step.
- **Log errors**, by level and PostgreSQL class.
- **First signals:** the first moment in the step that each service showed a
  limit-shaped symptom, in time order:
  - an HTTP 429 or 5xx;
  - an ERROR, CRITICAL, FATAL or PANIC line, or a named PostgreSQL error class;
  - a lock wait, timed from when the wait began;
  - connections at 90 % of `max_connections`;
  - blocked, rejected or evicted Redis clients or keys, or Redis at 90 % of
    its client or memory limit;
  - a container restart, an OOM kill, or CPU at 90 % of its limit (or of the
    host's CPUs);
  - a failed probe.

The report names no cause. The first signals are evidence to correlate.

### Precision and gaps

- Counters are cut at the samples nearest the step's edges, so up to one
  interval of a neighbour's activity can be included.
- Log counts are cut to the second.
- First times are exact.
- Access lines carry no latency, so the report has none: latency is the
  driver's to measure. Secrets runs with `--no-access-log` and the TLS front
  logs no requests, so neither appears under HTTP. Their failures show only in
  the driver's own accounting and in the container and database samples.

## Tests

```sh
python3 test_collect.py
python3 test_summarise.py
```

`fixtures/ramp-samples.jsonl` is a real recording. `test_summarise.py`'s
docstring says how it was made, and that its expected counts come from
`docker logs`, not from the collector.
