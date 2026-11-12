from pathlib import Path
import unittest
from vm_gate.local_guard import run_guard,targets
from vm_gate.source import prepare
from vm_gate.errors import Refused
from test_source import GitFixture,git

class LocalGuardTests(GitFixture,unittest.TestCase):
    def commit(self,make):
        (self.repo/'Makefile').write_text(make)
        (self.repo/'new').write_text(make)
        (self.repo/'scripts').mkdir(exist_ok=True)
        (self.repo/'scripts/candidate-suite.sh').write_text('checks() {\n run lint-fixture\n}\n')
        git(self.repo,'add','.');git(self.repo,'commit','-m','lint fixture')
        sha=git(self.repo,'rev-parse','HEAD')
        return prepare(self.repo,sha,self.root/'guard',observed=self.observed)
    def test_failure_is_a_local_refusal_with_original_output(self):
        source=self.commit('lint-fixture:\n\t@echo "I001 planted import-order failure"; exit 1\n')
        with self.assertRaisesRegex(Refused,'I001 planted'):run_guard(source,self.root/'guard')
    def test_exact_sha_guard_passes_without_using_current_checkout(self):
        source=self.commit('lint-fixture:\n\t@echo "All checks passed!"\n')
        (self.repo/'Makefile').write_text('lint-fixture:\n\t@exit 1\n');git(self.repo,'add','.');git(self.repo,'commit','-m','later bad head')
        receipt=run_guard(source,self.root/'guard')
        self.assertEqual(receipt['targets'],['lint-fixture'])
        self.assertIn('All checks passed!',receipt['pass_lines'])
    def test_guard_cannot_launch_a_container(self):
        source=self.commit('lint-fixture:\n\tdocker run --rm fixture-image true\n')
        with self.assertRaisesRegex(Refused,'containers are forbidden'):run_guard(source,self.root/'guard')
    def test_formatter_must_not_silently_change_the_selected_bytes(self):
        source=self.commit('lint-fixture:\n\t@echo changed >> new\n')
        with self.assertRaisesRegex(Refused,'changed the checkout'):run_guard(source,self.root/'guard')

if __name__=='__main__':unittest.main()
