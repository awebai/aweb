"""Portable Git/process controls; Docker commands are recorded, never executed."""

import json
import io
from contextlib import redirect_stdout
import os
import shutil
import signal
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_user_paths_local as local


class LocalUserPathsControls(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "docker.jsonl"
        docker = self.bin / "docker"
        docker.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
 stream.write(json.dumps(args) + '\\n')
if args[0] == 'info':
 assert os.environ.get('DOCKER_HOST') == 'unix:///admitted-local.sock'
 assert 'DOCKER_CONTEXT' not in os.environ
 print('/fixture/docker-data')
elif args[:2] == ['image', 'ls']:
 if not os.environ.get('MISSING_IMAGE'): print('image-id')
elif args[:2] == ['image', 'inspect']:
 print(json.dumps([{'Id':'sha256:prepared', 'Config':{'Labels':{
 'aweb.user-paths-ready':'1', 'aweb.user-paths-source-tree':os.environ['TREE'],
 'aweb.user-paths-source-sha':os.environ['SHA']}}}]))
elif args[0] == 'build':
 context=Path(args[-1])
 Path(os.environ['BUILD_OBSERVATION']).write_text(json.dumps({
 'files': sorted(str(p.relative_to(context)) for p in context.rglob('*') if p.is_file()),
 'body': (context/'source.txt').read_text(), 'args':args,
 'builder':os.environ.get('BUILDX_BUILDER'), 'buildkit':os.environ.get('BUILDKIT_HOST'),
 'docker_host':os.environ.get('DOCKER_HOST')}))
elif args[0] == 'cp':
 if os.environ.get('COPY_FAIL'):
  sys.exit(17)
 Path(args[-1]).write_bytes(b'linux-candidate')
elif args[0] not in ('create', 'rm'):
 sys.exit('unexpected Docker operation: ' + repr(args))
""")
        docker.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            CALLS=str(self.calls),
            TREE="b" * 40,
            SHA="a" * 40,
        )
        self.env.pop("DOCKER_CONTEXT", None)
        self.env.update(
            DOCKER_HOST="unix:///admitted-local.sock",
            DISK_USED=str(self.root / "disk-used"),
            AWEB_GATE_MIN_FREE_GB="50",
            AWEB_GATE_RESERVE_GB="30",
        )
        for name, body in {
            "uname": "#!/bin/sh\necho Linux\n",
            "df": '#!/bin/sh\necho \'Filesystem 1024-blocks Used Available Capacity Mounted\'\nif [ -f "$DISK_USED" ]; then free=1048576; else free=104857600; fi\necho "fixture 200000000 0 $free 0% /fixture"\n',
        }.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.source = local.Source(commit="a" * 40, tree="b" * 40)

    def test_wrong_source_runtime_refuses_without_build_or_project(self):
        for key in ("TREE", "SHA"):
            with self.subTest(key=key):
                env = dict(self.env, **{key: "c" * 40})
                with self.assertRaisesRegex(
                    local.Refused, "Unset USER_PATHS_RUNTIME_IMAGE"
                ):
                    local.prepare_runtime(
                        root=self.root,
                        source=self.source,
                        evidence=self.root,
                        environ=env,
                        reference="explicit-image",
                    )
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(call[0] == "image" for call in calls))
        image = local.prepare_runtime(
            root=self.root,
            source=self.source,
            evidence=self.root,
            environ=self.env,
            reference="explicit-image",
        )
        self.assertEqual(image, "sha256:prepared")

    def test_runtime_build_uses_exact_git_archive_and_source_arguments(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "source.txt").write_text("committed source")
        subprocess.run(["git", "-C", str(self.root), "add", "source.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "source",
            ],
            check=True,
        )

        def git(revision):
            return subprocess.check_output(
                ["git", "-C", str(self.root), "rev-parse", revision], text=True
            ).strip()

        source = local.Source(commit=git("HEAD"), tree=git("HEAD^{tree}"))
        # The builder is given the captured commit, never a directory containing local artifacts.
        (self.root / "source.txt").write_text("changed since capture")
        observation = self.root / "build.json"
        env = dict(
            self.env,
            MISSING_IMAGE="1",
            BUILDX_BUILDER="unrelated-remote-builder",
            BUILDKIT_HOST="tcp://remote:1234",
            DOCKER_HOST="unix:///admitted-local.sock",
            BUILD_OBSERVATION=str(observation),
            SHA=source.commit,
            TREE=source.tree,
        )
        self.assertEqual(
            local.prepare_runtime(
                root=self.root,
                source=source,
                evidence=self.root,
                environ=env,
                reference=None,
            ),
            "sha256:prepared",
        )
        observed = json.loads(observation.read_text())
        self.assertIsNone(observed["builder"])
        self.assertIsNone(observed["buildkit"])
        self.assertEqual(observed["docker_host"], "unix:///admitted-local.sock")
        self.assertEqual(observed["files"], ["source.txt"])
        self.assertEqual(observed["body"], "committed source")
        self.assertIn("USER_PATHS_SOURCE_TREE=" + source.tree, observed["args"])
        self.assertIn("USER_PATHS_SOURCE_SHA=" + source.commit, observed["args"])
        self.assertFalse(
            Path(observed["args"][-1]).exists(), "build scratch is removed"
        )

    def test_binary_copy_failure_removes_only_its_own_container(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                env = dict(self.env)
                if fail:
                    env["COPY_FAIL"] = "1"
                    with self.assertRaises(local.Refused):
                        local.export_candidate(
                            image="sha256:prepared",
                            destination=self.root / "candidate",
                            environ=env,
                        )
                else:
                    local.export_candidate(
                        image="sha256:prepared",
                        destination=self.root / "candidate",
                        environ=env,
                    )
                    self.assertEqual(
                        (self.root / "candidate").read_bytes(), b"linux-candidate"
                    )
                calls = [
                    json.loads(line) for line in self.calls.read_text().splitlines()
                ]
                created = [
                    call[call.index("--name") + 1]
                    for call in calls
                    if call[0] == "create"
                ]
                removed = [call[-1] for call in calls if call[0] == "rm"]
                self.assertEqual(created, removed)

    def test_real_lane_processes_have_separate_inputs_and_preserve_failure(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "e2e-user-paths.sh").write_text("""#!/bin/sh
python3 - <<'CHILD'
import json, os, sys
from pathlib import Path
p=Path(os.environ['USER_PATHS_EVIDENCE']); p.mkdir(parents=True)
(p/'received.json').write_text(json.dumps(dict(os.environ)))
(p/'cleanup.txt').write_text('owned cleanup reached')
sys.exit(7 if p.parent.name == 'head-1.36.40' else 0)
CHILD
""")
        metadata = {}
        for version in local.RELEASES:
            path = self.root / (version + ".json")
            path.write_text(json.dumps({"version": version}))
            metadata[version] = path
        env = dict(
            self.env,
            USER_PATHS_BASELINE_WHEEL="must-not-leak",
            CANDIDATE_SOURCE_SHA="must-not-leak",
            USER_PATHS_COMPARISON_METADATA="must-not-leak",
        )
        rows = local.run_lanes(
            root=self.root,
            evidence=self.root / "evidence",
            source=self.source,
            image="sha256:prepared",
            candidate=self.root / "candidate",
            metadata=metadata,
            environ=env,
        )
        self.assertEqual([row.exit_code for row in rows], [0, 7, 0])
        for row in rows:
            observed = json.loads((row.evidence / "stack/received.json").read_text())
            self.assertEqual(
                (row.evidence / "stack/cleanup.txt").read_text(),
                "owned cleanup reached",
            )
            self.assertNotIn("CANDIDATE_SOURCE_SHA", observed)
            self.assertNotIn("USER_PATHS_BASELINE_WHEEL", observed)
            self.assertNotIn("USER_PATHS_COMPARISON_METADATA", observed)
            self.assertEqual(observed["USER_PATHS_RUNTIME_IMAGE"], "sha256:prepared")
            if row.lane is local.Lane.FORWARD_REVERSE:
                self.assertEqual(
                    observed["USER_PATHS_CANDIDATE_SHA"], self.source.commit
                )
            else:
                self.assertNotIn("USER_PATHS_CANDIDATE_BIN", observed)
                self.assertIn(
                    row.lane.value.removeprefix("head-"),
                    observed["USER_PATHS_LATEST_METADATA"],
                )

    def test_later_disk_refusal_stops_before_next_stack(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "e2e-user-paths.sh").write_text("""#!/bin/sh
mkdir -p "$USER_PATHS_EVIDENCE"
echo executed > "$USER_PATHS_EVIDENCE/ran"
touch "$DISK_USED"
""")
        metadata = {}
        for version in local.RELEASES:
            path = self.root / (version + ".json")
            path.write_text("{}")
            metadata[version] = path
        # Real admission owner + real shell floor calculation; only Docker/df are receivers.
        local.check_docker(environ=self.env)
        output = io.StringIO()
        with (
            redirect_stdout(output),
            self.assertRaisesRegex(local.Refused, "1.0 GiB free"),
        ):
            local.run_lanes(
                root=self.root,
                evidence=self.root / "evidence",
                source=self.source,
                image="fixture",
                candidate=self.root / "candidate",
                metadata=metadata,
                environ=self.env,
            )
        first = self.root / "evidence/head-1.36.58"
        second = self.root / "evidence/head-1.36.40"
        self.assertTrue((first / "stack/ran").is_file())
        self.assertEqual(json.loads((first / "exit.json").read_text()), {"exit": 0})
        self.assertFalse((second / "stack").exists())
        self.assertFalse(
            (second / "exit.json").exists(),
            "no invented stack exit for a refused admission",
        )
        diagnostic = (second / "preflight.log").read_text()
        self.assertIn("need 80 GiB", diagnostic)
        self.assertIn("docker system prune", diagnostic)
        self.assertIn("fstrim", diagnostic)
        self.assertIn("head-1.36.58: PASS", output.getvalue())
        self.assertIn("head-1.36.40: NOT_RUN (preflight failed)", output.getvalue())
        self.assertIn("forward-reverse: NOT_RUN", output.getvalue())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(sum(call[0] == "info" for call in calls), 3)

    def test_real_entry_checks_disk_before_any_preparation(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in (
            "test_user_paths_local.py",
            "test_server_local.py",
            "local_suite_slots.py",
            "fetch_released_aw.py",
        ):
            shutil.copy2(local.ROOT / "scripts" / name, scripts / name)
        (scripts / "candidate-docker-gate.sh").write_text(
            "echo disk-floor-refusal; exit 41\n"
        )
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "scripts"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "import local_suite_slots; local_suite_slots.SLOT_DIRECTORY=Path(sys.argv[1]).parent/'slots'; "
                "import test_user_paths_local; sys.exit(test_user_paths_local.main())",
                str(scripts),
            ],
            env={
                key: value
                for key, value in dict(
                    self.env, DOCKER_HOST="unix:///local-fixture.sock"
                ).items()
                if key != "DOCKER_CONTEXT"
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("disk-floor-refusal", result.stderr)
        self.assertIn("docker system prune", result.stderr)
        self.assertIn("fstrim", result.stderr)
        self.assertFalse(
            self.calls.exists(), "no image/project operation before the disk guard"
        )

    def test_real_interruption_waits_for_owned_child_cleanup(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "e2e-user-paths.sh").write_text(
            'exec python3 "$(dirname "$0")/child.py"\n'
        )
        (scripts / "child.py").write_text("""import os, signal, time
from pathlib import Path
p=Path(os.environ['USER_PATHS_EVIDENCE']); p.mkdir(parents=True)
def stop(number, frame):
 raise SystemExit(128+number)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
 (p/'ready').touch()
 while True: time.sleep(.1)
finally:
 signal.signal(signal.SIGTERM, signal.SIG_IGN)
 time.sleep(.2)
 (p/'cleanup').touch()
""")
        driver = self.root / "driver.py"
        driver.write_text("""import signal, sys, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import test_user_paths_local as local
root=Path(sys.argv[2]); metadata={}
for version in local.RELEASES:
 p=root/(version+'.json'); p.write_text('{}'); metadata[version]=p
for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, local.interrupted)
try:
 local.run_lanes(root=root, evidence=root/'evidence', source=local.Source(commit='a'*40,tree='b'*40), image='fixture', candidate=root/'candidate',metadata=metadata,environ=json.loads(sys.argv[3]))
except local.Interrupted as error:
 sys.exit(128+error.number)
""")
        with subprocess.Popen(
            [
                sys.executable,
                str(driver),
                str(local.ROOT / "scripts"),
                str(self.root),
                json.dumps(self.env),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ) as child:
            ready = self.root / "evidence/head-1.36.58/stack/ready"
            try:
                deadline = time.monotonic() + 10
                while (
                    not ready.exists()
                    and child.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                child.send_signal(signal.SIGTERM)
                output, _ = child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
            self.assertEqual(child.returncode, 143, output)
            self.assertTrue(ready.with_name("cleanup").exists())
            self.assertIn("head-1.36.58: INTERRUPTED", output)
            self.assertIn("head-1.36.40: NOT_RUN", output)
            self.assertFalse((self.root / "evidence/head-1.36.40").exists())

    def test_real_git_rejects_dirty_source_instead_of_reusing_committed_image(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "--allow-empty",
                "-qm",
                "source",
            ],
            check=True,
        )
        # Ignore the command stand-in: it is not product source.
        (self.root / ".git/info/exclude").write_text("bin/\n")
        source = local.source_identity(root=self.root)
        self.assertEqual(len(source.commit), 40)
        (self.root / "uncommitted.py").write_text("x=1\n")
        with self.assertRaisesRegex(local.Refused, "Commit or remove"):
            local.source_identity(root=self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
