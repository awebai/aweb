from pathlib import Path
import io
import json
import tarfile
import tempfile
import unittest
from vm_gate.evidence import collect_archive
from vm_gate.errors import Infrastructure

SHA='a'*40
class EvidenceTests(unittest.TestCase):
    def archive(self,files):
        memory=io.BytesIO()
        with tarfile.open(fileobj=memory,mode='w:gz') as t:
            for name,data in files.items():
                data=data.encode();item=tarfile.TarInfo(name);item.size=len(data);t.addfile(item,io.BytesIO(data))
        path=Path(self.tmp.name)/'evidence.tar.gz';path.write_bytes(memory.getvalue());return path
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
    def test_nested_fixture_pass_cannot_override_actual_sha_failure(self):
        main=f'tmp/aweb-candidate-gate-{SHA}-run/summary.tsv'
        other='tmp/aweb-candidate-gate-'+('b'*40)+'-nested/summary.tsv'
        archive=self.archive({main:'unit\tFAILED\tunit.log\t23s\t900s\n',other:'unit\tPASSED\tunit.log\t0s\t900s\n'})
        result=collect_archive(archive,SHA,Path(self.tmp.name)/'unpacked')
        self.assertEqual(result['stages'],[{'stage':'unit','status':'FAILED','seconds':23.0,'summary':main}])
        self.assertTrue((Path(self.tmp.name)/'unpacked'/other).exists())
    def test_reused_stage_is_explicit_with_no_fabricated_duration(self):
        output=f'gate: tree {"b"*40} already passed checks; original log /retained/checks.log\n'
        archive=self.archive({'var/log/vm-gate/gate-output.log':output})
        result=collect_archive(archive,SHA,Path(self.tmp.name)/'out')
        self.assertEqual(result['stages'][0]['status'],'REUSED')
        self.assertIsNone(result['stages'][0]['seconds'])
        self.assertEqual(result['stages'][0]['original_log'],'/retained/checks.log')

    def test_archive_cannot_write_outside_evidence_directory(self):
        archive=self.archive({'../escaped':'wrong'})
        with self.assertRaisesRegex(Infrastructure,'unsafe archive'):collect_archive(archive,SHA,Path(self.tmp.name)/'out')
        self.assertFalse((Path(self.tmp.name)/'escaped').exists())
    def test_memory_uses_concurrent_current_sum_not_sum_of_individual_highwaters(self):
        samples=[{'meminfo_kib':{'MemTotal':100,'MemAvailable':50},'containers':[{'memory.current':'10','memory.peak':'100'},{'memory.current':'20','memory.peak':'200'}]},
                 {'meminfo_kib':{'MemTotal':100,'MemAvailable':40},'containers':[{'memory.current':'5','memory.peak':'100'},{'memory.current':'35','memory.peak':'200'}]}]
        archive=self.archive({'var/log/vm-gate/memory.jsonl':'\n'.join(json.dumps(s) for s in samples)})
        result=collect_archive(archive,SHA,Path(self.tmp.name)/'out')
        self.assertEqual(result['memory']['concurrent_cgroup_current_peak_sum_bytes'],40)
        self.assertEqual(result['memory']['host_sampled_used_peak_bytes'],60*1024)

if __name__=='__main__':unittest.main()
