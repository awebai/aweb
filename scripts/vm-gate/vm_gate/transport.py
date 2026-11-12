"""Per-server SSH identity and bounded transfers with a scrubbed child env."""
import ipaddress
import shutil
import os
from pathlib import Path
import subprocess
from .config import child_environment
from .errors import Infrastructure


class Transport:
    def __init__(self,directory,address,server_id):
        self.directory=Path(directory)
        self.address=str(ipaddress.IPv4Address(address))
        if type(server_id) is not int or server_id<=0:
            raise Infrastructure('invalid SSH server identity')
        self.options=['-F',os.devnull,'-i',str(self.directory/'ssh-key'),'-o','BatchMode=yes',
                      '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=accept-new',
                      '-o','UserKnownHostsFile='+str(self.directory/'known_hosts'),
                      '-o',f'HostKeyAlias=aweb-vm-gate-server-{server_id}',
                      '-o','ConnectTimeout=5','-o','ForwardAgent=no']

    @staticmethod
    def invoke(args,timeout,check=True):
        try:
            result=subprocess.run(args,timeout=timeout,text=True,capture_output=True,
                                  env=child_environment())
        except (OSError,subprocess.TimeoutExpired):
            raise Infrastructure('SSH operation unavailable or timed out') from None
        if check and result.returncode:
            raise Infrastructure(f'SSH operation failed (exit {result.returncode})')
        return result

    def run(self,command,*,timeout,check=True):
        return self.invoke([shutil.which('ssh') or 'ssh',*self.options,'root@'+self.address,command],timeout,check)

    def copy(self,source,target,*,timeout,download=False):
        remote='root@'+self.address+':'+str(source if download else target)
        args=[shutil.which('scp') or 'scp',*self.options,remote if download else str(source),
              str(target) if download else remote]
        return self.invoke(args,timeout)
