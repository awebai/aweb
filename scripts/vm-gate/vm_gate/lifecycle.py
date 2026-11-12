"""One run's saga. Resource deletion never depends on receiving evidence."""
from decimal import Decimal, ROUND_CEILING
import json
import math
from pathlib import Path
import time

from .errors import Infrastructure, Refused


def write_summary(directory, summary):
    path=Path(directory)/'summary.json'
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(summary,indent=2)+'\n');temporary.replace(path)


def run_session(*,provider,store,remote,run_id,owner,sha,budget,directory,
                server_type,hourly_eur,ip_hourly_eur,clock=time.time):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    summary={'run_id':run_id,'sha':sha,'server_type':server_type,'created':clock(),
             'expires':budget.expires,'exit':70,'infrastructure':'infrastructure',
             'stages':[],'resources':[],'memory':None}
    reserved=False;server=None;server_start=None;unknown_resources=False;cleanup_ok=False
    labels={'run_id':run_id,'owner':owner,'sha':sha,'expires':budget.expires}
    rate=Decimal(str(hourly_eur));ip_rate=Decimal(str(ip_hourly_eur))
    try:
        # The first provider operation for every admitted run is the reaper.
        summary['reaped']=provider.reap(clock())
        budget.require('setup',now=clock())
        hours=math.ceil((budget.expires-clock())/3600)
        reserve=(rate+ip_rate)*hours
        store.reserve(run_id,str(reserve),owner=owner,sha=sha,expires=budget.expires,now=clock())
        reserved=True
        summary['spend']=store.totals(now=clock())
        key=provider.create('create_key',run_id,labels=labels)
        summary['resources'].append(key)
        ip=provider.create('create_ip',run_id,labels=labels)
        summary['resources'].append(ip)
        server_start=clock()
        server=provider.create('create_server',run_id,server_type=server_type,
                               labels=labels,key=key,ip=ip)
        summary['server_id']=server['id'];summary['resources'].append(server)
        store.update(run_id,{'server_id':server['id'],'resources':summary['resources']})
        remote.prepare(server,timeout=budget.require('setup',now=clock()))
        summary['gate_started']=clock()
        result=remote.execute(server,timeout=budget.require('gate',now=clock()))
        if not isinstance(result,int) or result < 0 or result > 255:
            raise Infrastructure('remote gate returned an invalid exit status')
        summary.update(gate_exit=result,gate_finished=clock(),exit=result,infrastructure=None)
        evidence=remote.collect(server,timeout=budget.require('pull',now=clock()))
        summary.update(evidence)
        # Evidence may add stages/memory, never change verdict identity.
        summary.update(exit=result,infrastructure=None,sha=sha,run_id=run_id)
    except BaseException as exc:
        if isinstance(exc,(Refused,Infrastructure)):
            summary.update(exit=int(exc.exit_code),infrastructure=exc.classification,error=str(exc))
            unknown_resources=hasattr(exc,'resources') and exc.resources is None
            found=getattr(exc,'resources',None)
            if found:
                known={(x['kind'],x['id']) for x in summary['resources']}
                summary['resources'].extend(x for x in found if (x['kind'],x['id']) not in known)
                server=next((x for x in found if x['kind']=='server'),server)
                if server:summary['server_id']=server['id']
        else:
            summary.update(exit=70,infrastructure='infrastructure',error=type(exc).__name__)
    finally:
        try:
            summary['cleanup']=provider.cleanup(run_id)
            cleanup_ok=True
        except BaseException as exc:
            summary.update(exit=70,infrastructure='infrastructure',cleanup_error=type(exc).__name__)
        summary['finished']=clock()
        if reserved and cleanup_ok and not unknown_resources:
            # An accepted server has a one-hour minimum, even if it failed early.
            hours=max(1,math.ceil((clock()-server_start)/3600)) if server else 0
            ip_hours=max(1,math.ceil((clock()-summary['created'])/3600)) if any(x['kind']=='ip' for x in summary['resources']) else 0
            actual=rate*hours+ip_rate*ip_hours
            try:
                store.settle(run_id,str(actual),now=clock())
                summary['cost_eur']=str(actual)
                summary['spend']=store.totals(now=clock())
            except BaseException as exc:
                summary.update(exit=70,infrastructure='infrastructure',settlement_error=type(exc).__name__)
        else:
            summary['cost_eur']=None
            summary['reservation_held']=reserved
        summary['total_seconds']=summary['finished']-summary['created']
        write_summary(directory,summary)
    return summary
