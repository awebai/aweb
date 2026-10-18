"""Opt-in integration test: real Hermes, aw, local e2e server and PostgreSQL.

Requires HERMES_AGENT_SOURCE, HERMES_LIVE_RECEIVER_HOME,
HERMES_LIVE_SENDER_HOME and HERMES_LIVE_POSTGRES_CONTAINER. Run with the
Hermes dependency environment; no other gateway may consume the receiver.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


REQUIRED = ("HERMES_AGENT_SOURCE", "HERMES_LIVE_RECEIVER_HOME",
            "HERMES_LIVE_SENDER_HOME", "HERMES_LIVE_POSTGRES_CONTAINER")


@unittest.skipUnless(all(os.environ.get(k) for k in REQUIRED), "requires isolated local integration fixtures")
class LiveChatTests(unittest.TestCase):
    def test_unread_burst_and_stream_restart(self):
        source, receiver, sender = (Path(os.environ[k]).resolve() for k in REQUIRED[:3])
        container = os.environ[REQUIRED[3]]
        from ruamel.yaml import YAML

        config = YAML(typ="safe").load((receiver / ".aw/workspace.yaml").read_text())
        self.assertTrue(config["aweb_url"].startswith("http://127.0.0.1:"), "local fixture only")
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("AWEB_", "AWID_", "HERMES_"))
               and not k.endswith(("API_KEY", "TOKEN"))}

        def aw(home, *args):
            return subprocess.run(["aw", *args, "--json"], cwd=home, env=env,
                                  capture_output=True, text=True, check=True, timeout=10).stdout

        def sql(query):
            return subprocess.run(["docker", "exec", container, "psql", "-U", "aweb", "-d", "aweb",
                                   "-At", "-c", query], capture_output=True, text=True,
                                  check=True, timeout=10).stdout.strip()

        with tempfile.TemporaryDirectory(prefix="hermes-aweb-live-") as temp:
            temp = Path(temp)
            body = temp / "body.md"
            body.write_text("/help first")
            first = json.loads(aw(sender, "chat", "send-and-leave", "hermes", "--plaintext",
                                  "--start-conversation", "--body-file", str(body)))
            session = first["session_id"]
            body.write_text("/help second")
            second = json.loads(aw(sender, "chat", "send", "--session-id", session,
                                   "--plaintext", "--leave", "--body-file", str(body)))
            ids = [first["message_id"], second["message_id"]]
            events = [json.loads(line) for line in aw(receiver, "events", "stream", "--timeout", "1").splitlines()]
            summary = next(e for e in events if e.get("type") == "actionable_chat" and e.get("session_id") == session)
            self.assertNotIn("message_id", summary)
            self.assertEqual(summary["unread_count"], 2)

            # Hold the second read receipt at the REAL database FK boundary so
            # the stream can be restarted deterministically in the middle of the burst.
            lock = subprocess.Popen(["docker", "exec", "-i", container, "psql", "-U", "aweb", "-d", "aweb", "-At"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            lock.stdin.write(f"BEGIN; SELECT message_id FROM aweb.chat_messages WHERE message_id='{ids[1]}' FOR UPDATE;\n\\echo LOCKED\n")
            lock.stdin.flush()
            while lock.stdout.readline().strip() != "LOCKED":
                if lock.poll() is not None:
                    self.fail("local database lock failed")

            plugin_dir = temp / "plugins/platforms"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "aweb").symlink_to(Path(__file__).resolve().parents[1])
            (temp / "config.yaml").write_text("_config_version: 12\nplugins:\n  enabled: [platforms/aweb]\ngateway:\n  unauthorized_dm_behavior: ignore\n  platforms:\n    aweb:\n      enabled: true\n")
            env.update(HERMES_HOME=str(temp), PYTHONPATH=str(source),
                       AWEB_PLATFORM_ENABLED="true", AWEB_PLATFORM_WORKDIR=str(receiver),
                       AWEB_ALLOWED_USERS=summary["from_address"], AWEB_ALLOW_ALL_USERS="false")
            log = open(temp / "gateway.log", "w+")
            gateway = subprocess.Popen([sys.executable, "-m", "hermes_cli.main", "gateway", "run"],
                                       cwd=temp, env=env, stdout=log, stderr=subprocess.STDOUT)

            def rows():
                return json.loads(sql(f"SELECT coalesce(json_agg(x ORDER BY x.created_at),'[]') FROM (SELECT message_id,from_alias,created_at,(SELECT read_at FROM aweb.chat_message_reads r WHERE r.message_id=m.message_id AND r.did<>m.from_did LIMIT 1) AS read_at FROM aweb.chat_messages m WHERE session_id='{session}') x"))

            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    current = rows()
                    if next(r for r in current if r["message_id"] == ids[0])["read_at"]:
                        break
                    time.sleep(.1)
                else:
                    self.fail("first unread message never received a reply/read receipt")
                self.assertIsNone(next(r for r in current if r["message_id"] == ids[1])["read_at"])
                def streams():
                    processes = subprocess.check_output(["ps", "-axo", "pid=,ppid=,command="], text=True)
                    return {int(p[0]) for line in processes.splitlines()
                            if len(p := line.split(None, 2)) == 3 and int(p[1]) == gateway.pid
                            and "aw events stream" in p[2]}

                stream_pid = next(iter(streams()))
                os.kill(stream_pid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    replacement = streams() - {stream_pid}
                    if replacement:
                        break
                    time.sleep(.1)
                else:
                    self.fail("gateway did not restart its aw event stream")
                lock.stdin.write("COMMIT;\n\\q\n")
                lock.stdin.flush()
                lock.communicate(timeout=5)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    current = rows()
                    incoming = [r for r in current if r["message_id"] in ids]
                    if all(r["read_at"] for r in incoming):
                        break
                    time.sleep(.1)
                else:
                    self.fail("burst did not drain after stream restart")
                outgoing = [r for r in current if r["from_alias"] == "hermes"]
                self.assertEqual(len(outgoing), 2, "each inbound gets exactly one real gateway reply")
                for inbound, reply in zip(incoming, outgoing):
                    self.assertGreaterEqual(inbound["read_at"], reply["created_at"])
                self.assertLess(incoming[0]["read_at"], incoming[1]["read_at"])
                body.write_text("/help after restart")
                third = json.loads(aw(sender, "chat", "send", "--session-id", session,
                                     "--plaintext", "--leave", "--body-file", str(body)))
                ids.append(third["message_id"])
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    current = rows()
                    if next(r for r in current if r["message_id"] == ids[-1])["read_at"]:
                        break
                    time.sleep(.1)
                else:
                    self.fail("new input was not delivered through the replacement stream")
                self.assertEqual(len([r for r in current if r["from_alias"] == "hermes"]), 3)
                body.write_text("/start")  # Real Hermes command with an intentionally empty response.
                no_reply = json.loads(aw(sender, "chat", "send", "--session-id", session,
                                        "--plaintext", "--leave", "--body-file", str(body)))
                ids.append(no_reply["message_id"])
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    current = rows()
                    if next(r for r in current if r["message_id"] == ids[-1])["read_at"]:
                        break
                    time.sleep(.1)
                else:
                    self.fail("successful no-reply processing was not acknowledged")
                self.assertEqual(len([r for r in current if r["from_alias"] == "hermes"]), 3)
                print(json.dumps({"session_id": session, "input_ids": ids, "rows": current,
                                  "restarted_stream_pid": stream_pid, "replacement_stream_pid": next(iter(replacement))}))
            except BaseException:
                log.flush()
                print((temp / "logs/agent.log").read_text()[-12000:])
                raise
            finally:
                if lock.poll() is None:
                    lock.stdin.write("ROLLBACK;\n\\q\n")
                    lock.stdin.flush()
                    lock.communicate(timeout=5)
                gateway.send_signal(signal.SIGINT)
                try:
                    gateway.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    gateway.kill()
                    gateway.wait(timeout=5)
                log.close()


if __name__ == "__main__":
    unittest.main()
