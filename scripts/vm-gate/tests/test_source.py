import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from vm_gate.errors import Refused
from vm_gate.source import prepare, verify_train_main


def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.PIPE,text=True).strip()

class GitFixture:
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.repo=self.root/'repo';self.repo.mkdir()
        git(self.repo,'init','-b','main');git(self.repo,'config','user.email','fixture@example.invalid')
        git(self.repo,'config','user.name','Fixture')
        (self.repo/'cli/go').mkdir(parents=True);(self.repo/'candidate-gate').mkdir()
        (self.repo/'cli/go/go.mod').write_text('module fixture\ngo 1.2.3\n')
        (self.repo/'candidate-gate/Dockerfile').write_text('FROM python:3.12-slim\nARG GO_VERSION=1.2.3\nRUN node_22.x\nCOPY --from=ghcr.io/astral-sh/uv:0.1.2 /uv /bin/uv\n')
        git(self.repo,'add','.');git(self.repo,'commit','-m','base');self.main=git(self.repo,'rev-parse','HEAD')
        git(self.repo,'tag','fixture-base')
        self.remote=self.root/'remote.git';git(self.repo,'clone','--bare',str(self.repo),str(self.remote))
        git(self.repo,'remote','add','origin',str(self.remote));git(self.repo,'fetch','origin')
        (self.repo/'scripts').mkdir()
        (self.repo/'scripts/candidate-suite.sh').write_text('checks() {\n run lint-fixture\n}\n')
        (self.repo/'Makefile').write_text('lint-fixture:\n\t@echo \"All checks passed!\"\n')
        (self.repo/'new').write_text('candidate');git(self.repo,'add','.');git(self.repo,'commit','-m','candidate')
        self.sha=git(self.repo,'rev-parse','HEAD');self.out=self.root/'evidence'
        self.observed={'go':'1.2.3','uv':'0.1.2','node':'22','python':'3.12'}

class SourceTests(GitFixture, unittest.TestCase):
    def run_prepare(self,**kwargs):
        return prepare(self.repo,self.sha,self.out,observed=self.observed,**kwargs)

    def test_bundle_keeps_exact_candidate_real_main_and_tags_without_credentials(self):
        result=self.run_prepare(intent='train')
        self.assertEqual(result['real_main'],self.main)
        self.assertTrue(result['main_is_ancestor']);self.assertFalse(result['sha_is_on_main'])
        self.assertEqual(result['scope'],'train candidate')
        restored=self.root/'restore.git';git(self.repo,'init','--bare',str(restored))
        git(restored,'fetch',result['bundle'],'refs/*:refs/*')
        self.assertEqual(git(restored,'rev-parse',result['source_ref']),self.sha)
        self.assertEqual(git(restored,'rev-parse','refs/remotes/origin/main'),self.main)
        self.assertEqual(git(restored,'rev-parse','refs/tags/fixture-base'),self.main)
        self.assertNotIn(str(self.remote),Path(result['bundle']).read_bytes().decode('latin1'))
        self.assertEqual(git(self.repo,'for-each-ref','--format=%(refname)','refs/vm-gate'),'')

    def test_dirty_checkout_refuses_before_bundle(self):
        (self.repo/'untracked').write_text('dirty')
        with self.assertRaisesRegex(Refused,'dirty'):self.run_prepare()
        self.assertFalse((self.out/'source.bundle').exists())

    def test_unknown_sha_refuses(self):
        with self.assertRaisesRegex(Refused,'unknown SHA'):
            prepare(self.repo,'f'*40,self.out,observed=self.observed)

    def test_mismatch_refuses_locally_without_bundle(self):
        self.observed['go']='other'
        with self.assertRaisesRegex(Refused,'vm-gate snapshot'):self.run_prepare()
        self.assertFalse((self.out/'source.bundle').exists())

    def test_branch_scope_does_not_claim_real_main_ancestry(self):
        result=self.run_prepare(intent='branch')
        self.assertEqual(result['scope'],'branch qualification')
        self.assertEqual(result['frozen_main'],self.sha)
        self.assertEqual(result['real_main'],self.main)

    def test_train_stale_remote_main_refuses(self):
        result=self.run_prepare(intent='train');git(self.repo,'push','origin','HEAD:main')
        with self.assertRaisesRegex(Refused,'stale train candidate'):verify_train_main(self.repo,result)

    def test_train_without_main_ancestry_refuses(self):
        git(self.repo,'checkout','--orphan','unrelated');git(self.repo,'commit','-m','unrelated')
        sha=git(self.repo,'rev-parse','HEAD')
        with self.assertRaisesRegex(Refused,'origin/main is not an ancestor'):
            prepare(self.repo,sha,self.out,observed=self.observed,intent='train')

    def test_parallel_source_freezes_share_the_repo_lease_but_keep_separate_bundles(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(prepare,self.repo,self.sha,self.root/str(i),observed=self.observed,
                                 lock_root=self.root/'state') for i in range(2)]
            results=[f.result() for f in futures]
        self.assertNotEqual(results[0]['bundle'],results[1]['bundle'])
        self.assertEqual([r['sha'] for r in results],[self.sha,self.sha])
        self.assertEqual(git(self.repo,'for-each-ref','--format=%(refname)','refs/vm-gate'),'')

if __name__=='__main__':unittest.main()
