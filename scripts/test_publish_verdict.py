#!/usr/bin/env python3
"""The publish set is the gated manifest's lane rows, only with a passing Cloud verdict.

The Cloud side is a fixture clone of a bare origin whose `candidate-oss-verdict`
target answers as AC's written interface states (ac 3ea99efe7,
scripts/candidate_oss.py: exit status plus stdout JSON with schema, cloud_tree,
oss_manifest_sha256, passed, keys, effective_inputs, evidence). Its answer and
the arguments it was asked with live outside the checkout, so the tests also
prove what OSS asked for and that the checkout itself is left untouched.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from publish_release import PublishRefusal, gated_publish_set

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = 'a' * 40
RELEASED = '1.36.58'
FIXTURE_TARGET = '''candidate-oss-verdict:
\t@printf '%s\\n' "$(CLOUD_TREE) $(OSS_MANIFEST_SHA256) $(EXPECTED_AW_RELEASED)" > "$$VERDICT_FIXTURE/asked"
\t@cat "$$VERDICT_FIXTURE/answer.json"
\t@exit $$(cat "$$VERDICT_FIXTURE/status")
'''


def git(*arguments: str, cwd: Path) -> str:
    return subprocess.run(['git', *arguments], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def commit_cloud(clone: Path, message: str) -> str:
    (clone / 'Makefile').write_text(FIXTURE_TARGET + f'# {message}\n')
    git('add', 'Makefile', cwd=clone)
    git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', message, cwd=clone)
    git('push', '-q', 'origin', 'HEAD:main', cwd=clone)
    return git('rev-parse', 'HEAD^{tree}', cwd=clone)


def write_artifacts(directory: Path) -> str:
    """A gated artifact set: two lanes' files, a stray wheel outside the manifest."""
    files = {
        'aweb-1.0.0-py3-none-any.whl': ('aweb', b'server wheel bytes'),
        'aweb-1.0.0.tar.gz': ('aweb', b'server sdist bytes'),
        'awid_service-0.5.0-py3-none-any.whl': ('awid-service', b'awid wheel bytes'),
        'awid_service-0.5.0.tar.gz': ('awid-service', b'awid sdist bytes'),
    }
    rows = []
    for name, (package, payload) in files.items():
        (directory / name).write_bytes(payload)
        version = '1.0.0' if package == 'aweb' else '0.5.0'
        rows.append(dict(path=name, package=package, version=version,
                         sha256=hashlib.sha256(payload).hexdigest()))
    (directory / 'aweb-1.0.0-py2-none-any.whl').write_bytes(b'stray bytes never gated')
    manifest = json.dumps(dict(schema=2, source_sha=SOURCE_SHA, source_tree='b' * 40,
                               build_inputs={}, files=rows), indent=2, sort_keys=True) + '\n'
    (directory / 'manifest.json').write_text(manifest)
    return hashlib.sha256(manifest.encode()).hexdigest()


def verdict(digest: str, tree: str, released: str = RELEASED, *, passed: bool = True) -> dict:
    key = f'{tree}-{"e" * 64}'
    return dict(schema=1, cloud_tree=tree, oss_manifest_sha256=digest, passed=passed,
                keys=[key] if passed else [],
                effective_inputs={key: {'oss-manifest-sha256': digest, 'aw-released': released}} if passed else {},
                evidence=[])


class GatedPublishSet(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.artifacts = base / 'artifacts'
        self.artifacts.mkdir()
        self.digest = write_artifacts(self.artifacts)
        self.origin = base / 'cloud-origin.git'
        git('init', '-q', '--bare', '-b', 'main', str(self.origin), cwd=base)
        self.cloud = base / 'cloud'
        git('clone', '-q', str(self.origin), str(self.cloud), cwd=base)
        self.tree = commit_cloud(self.cloud, 'gated Cloud main')
        self.fixture = base / 'verdict'
        self.fixture.mkdir()
        environment = patch.dict(os.environ, VERDICT_FIXTURE=str(self.fixture))
        environment.start()
        self.addCleanup(environment.stop)

    def answer(self, document: dict | None, status: int = 0) -> None:
        (self.fixture / 'answer.json').write_text('' if document is None else json.dumps(document) + '\n')
        (self.fixture / 'status').write_text(f'{status}\n')

    def publish_set(self, *, digest: str | None = None, released: str = RELEASED, npm_latest: str = RELEASED,
                    prefix: str = 'server-v', source_sha: str = SOURCE_SHA, tree: str | None = None) -> list[dict]:
        return gated_publish_set(self.artifacts, prefix=prefix, version='1.0.0', source_sha=source_sha,
                                 cloud_checkout=self.cloud, cloud_tree=tree or self.tree,
                                 manifest_sha256=digest or self.digest, expected_aw_released=released,
                                 npm_latest_aw=npm_latest)

    def refuses(self, needle: str, **arguments) -> None:
        with self.assertRaises(PublishRefusal) as refusal:
            self.publish_set(**arguments)
        self.assertIn(needle, str(refusal.exception))

    def test_no_verdict_refuses(self):
        self.answer(verdict(self.digest, self.tree, passed=False), status=1)
        self.refuses('Cloud verdict')
        self.answer(None, status=2)
        self.refuses('Cloud verdict')
        self.answer(verdict(self.digest, self.tree, passed=False) | {'reason': 'gate-in-progress'})
        self.refuses('Cloud verdict')

    def test_verdict_for_another_manifest_digest_refuses(self):
        other = 'f' * 64
        self.answer(verdict(other, self.tree))
        self.refuses('Cloud verdict')
        answer = verdict(self.digest, self.tree)
        for inputs in answer['effective_inputs'].values():
            inputs['oss-manifest-sha256'] = other
        self.answer(answer)
        self.refuses('Cloud verdict')

    def test_manifest_digest_other_than_requested_refuses_before_asking_cloud(self):
        self.answer(verdict('f' * 64, self.tree))
        self.refuses('manifest.json sha256', digest='f' * 64)
        self.assertFalse((self.fixture / 'asked').exists(), 'Cloud was asked about unverified bytes')

    def test_different_aw_released_refuses(self):
        self.answer(verdict(self.digest, self.tree, released='1.36.57'))
        self.refuses('Cloud verdict')

    def test_npm_latest_aw_other_than_expected_refuses_before_asking_cloud(self):
        self.answer(verdict(self.digest, self.tree))
        self.refuses('npm latest', npm_latest='1.36.59')
        self.assertFalse((self.fixture / 'asked').exists(), 'Cloud was asked with an expectation npm contradicts')

    def test_verdict_naming_another_cloud_tree_refuses(self):
        self.answer(verdict(self.digest, 'd' * 40))
        self.refuses('Cloud verdict')

    def test_cloud_tree_that_is_not_current_main_refuses(self):
        gated = self.tree
        self.answer(verdict(self.digest, gated))
        head = git('rev-parse', 'HEAD', cwd=self.cloud)
        branches = git('for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', cwd=self.cloud)
        mover = self.cloud.parent / 'mover'
        git('clone', '-q', str(self.origin), str(mover), cwd=self.cloud.parent)
        commit_cloud(mover, 'Cloud main moved after the gate')
        self.refuses('Cloud main', tree=gated)
        self.assertFalse((self.fixture / 'asked').exists(), 'Cloud was asked about a tree that is not main')
        self.assertEqual(git('rev-parse', 'HEAD', cwd=self.cloud), head)
        self.assertEqual(git('for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', cwd=self.cloud),
                         branches)
        self.assertEqual(git('status', '--porcelain', cwd=self.cloud), '')

    def test_file_changed_after_gating_refuses(self):
        self.answer(verdict(self.digest, self.tree))
        (self.artifacts / 'aweb-1.0.0.tar.gz').write_bytes(b'rebuilt sdist bytes')
        self.refuses('aweb-1.0.0.tar.gz')

    def test_manifest_for_another_source_commit_refuses(self):
        self.answer(verdict(self.digest, self.tree))
        self.refuses('source commit', source_sha='9' * 40)

    def test_lane_missing_from_manifest_refuses(self):
        self.answer(verdict(self.digest, self.tree))
        self.refuses('@awebai/claude-channel', prefix='channel-v')

    def test_valid_verdict_publishes_exactly_the_lane_manifest_rows(self):
        self.answer(verdict(self.digest, self.tree))
        selected = self.publish_set()
        self.assertEqual(
            sorted((Path(row['path']).name, row['sha256']) for row in selected),
            sorted((name, hashlib.sha256((self.artifacts / name).read_bytes()).hexdigest())
                   for name in ('aweb-1.0.0-py3-none-any.whl', 'aweb-1.0.0.tar.gz')))
        self.assertTrue(all(Path(row['path']).parent == self.artifacts for row in selected))
        self.assertEqual((self.fixture / 'asked').read_text().split(), [self.tree, self.digest, RELEASED])
        self.assertEqual(git('status', '--porcelain', cwd=self.cloud), '')


class MandatoryInputs(unittest.TestCase):
    REQUIRED = ('CANDIDATE_ARTIFACT_DIR', 'CLOUD_CHECKOUT', 'CLOUD_TREE', 'OSS_MANIFEST_SHA256', 'EXPECTED_AW_RELEASED')

    def test_each_missing_input_exits_2_before_publishing(self):
        complete = dict(TAG='server-v1.0.0', CANDIDATE_ARTIFACT_DIR='/nonexistent/artifacts',
                        CLOUD_CHECKOUT='/nonexistent/cloud', CLOUD_TREE='c' * 40,
                        OSS_MANIFEST_SHA256='0' * 64, EXPECTED_AW_RELEASED=RELEASED)
        with tempfile.TemporaryDirectory() as temporary:
            shim = Path(temporary) / 'python3'
            shim.write_text('#!/bin/sh\ntouch "$PUBLISH_CALLED"\nexit 0\n')
            shim.chmod(0o755)
            called = Path(temporary) / 'called'
            environment = {name: value for name, value in os.environ.items() if name not in complete}
            environment.update(PATH=f'{temporary}{os.pathsep}{os.environ["PATH"]}', PUBLISH_CALLED=str(called))
            for missing in self.REQUIRED:
                with self.subTest(missing=missing):
                    assignments = [f'{name}={value}' for name, value in complete.items() if name != missing]
                    result = subprocess.run(['make', '--no-print-directory', '-C', str(ROOT), 'release-publish',
                                             *assignments], env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(f'{missing}=', result.stderr)
                    self.assertFalse(called.exists(), f'publisher ran without {missing}')


if __name__ == '__main__':
    unittest.main()
