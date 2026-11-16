"""Only live private commands remain; enrollment completion is person-signed."""

import inspect
import subprocess
import sys

import pytest

from aweb_key_holder.enrollment import Holder


@pytest.mark.parametrize('command',['bind','finish','activate','authorize'])
def test_retired_operator_commands_are_not_accepted(command,tmp_path):
    result=subprocess.run([sys.executable,'-m','aweb_key_holder.cli','--state',str(tmp_path/'absent'),command,'--help'],capture_output=True,text=True,check=False)
    assert result.returncode==2
    assert 'invalid choice' in result.stderr


@pytest.mark.parametrize('command',['bootstrap','issue-person'])
def test_live_private_issuance_commands_remain_available(command,tmp_path):
    result=subprocess.run([sys.executable,'-m','aweb_key_holder.cli','--state',str(tmp_path/'absent'),command,'--help'],capture_output=True,text=True,check=False)
    assert result.returncode==0


def test_controller_authorizer_and_privileged_completion_defaults_are_gone():
    assert not hasattr(Holder,'authorize_bootstrap')
    for operation in [Holder.bind_registration,Holder.finish_creation,Holder.finish,Holder.activate]:
        assert inspect.signature(operation).parameters['caller'].default is inspect.Parameter.empty
