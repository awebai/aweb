import os
from pathlib import Path
import subprocess
import sys
import unittest

class SignalTests(unittest.TestCase):
    def test_second_termination_during_cleanup_cannot_leave_resources(self):
        code='''
import os,signal,tempfile
from pathlib import Path
from test_lifecycle import Backend,Remote
from vm_gate.lifecycle import run_session
from vm_gate.provider import Provider
from vm_gate.state import Store
from vm_gate.expiry import CompletionBudget

def interrupted(*args):raise KeyboardInterrupt
signal.signal(signal.SIGTERM,interrupted)
b=Backend();original=b.delete;once=[]
def delete(item):
 if not once:once.append(True);os.kill(os.getpid(),signal.SIGTERM)
 original(item)
b.delete=delete
with tempfile.TemporaryDirectory() as tmp:
 s=Store(Path(tmp)/'db',150,clock=lambda:100)
 result=run_session(provider=Provider(b),store=s,remote=Remote(),run_id='r',owner='seat',sha='a'*40,
    budget=CompletionBudget(100,60),directory=Path(tmp)/'run',server_type='ccx33',
    hourly_eur='.2',ip_hourly_eur='.01',clock=lambda:100)
 assert b.items==[], 'second signal interrupted resource cleanup'
 assert result['cleanup']['exact_ids_absent']
'''
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,
            timeout=20,env={'PATH':os.defpath,'PYTHONPATH':str(root)+os.pathsep+str(root/'tests')})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
