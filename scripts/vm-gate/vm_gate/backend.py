"""Hetzner SDK boundary. Mutations have no SDK retries; labels own every ID."""
import time
from .errors import Infrastructure, Refused
from .provider import Provider

KINDS={'server':('servers','server'),'ip':('primary_ips','primary_ip'),
       'key':('ssh_keys','ssh_key'),'image':('images','image')}
PREFIX='aweb-gates.'


class Backend:
    def __init__(self,client,config):
        self.client=client;self.config=config
        # SDK's internal mutation retries must remain disabled.
        try:
            transport=client._client
            if not hasattr(transport,'_retry_max_retries'):
                raise AttributeError('unknown retry layout')
            transport._retry_max_retries=0
            if transport._retry_max_retries != 0:
                raise ValueError('retry setting did not change')
        except Exception:
            raise Infrastructure('SDK mutation retry setting unavailable or nonzero; refusing provider access') from None

    @staticmethod
    def labels(values):
        names={'run_id':'run','owner':'owner','sha':'sha','expires':'expires'}
        return {PREFIX+names[k]:str(values[k]) for k in names}

    @staticmethod
    def resource(kind,item):
        labels=item.get('labels',{})
        expiry=labels.get(PREFIX+'expires')
        try:expiry=int(expiry)
        except (TypeError,ValueError):expiry=None
        return {'kind':kind,'id':item['id'],'run_id':labels.get(PREFIX+'run'),
                'expires':expiry,'owner':labels.get(PREFIX+'owner'),
                'sha':labels.get(PREFIX+'sha'),'created':item.get('created')}

    def list(self,run_id=None):
        selector=PREFIX+'run'+('='+run_id if run_id else '')
        items=[]
        for kind,(plural,_) in KINDS.items():
            page=1;seen=set()
            while page:
                if page in seen or len(seen)>=1000:
                    raise Infrastructure('provider pagination did not terminate')
                seen.add(page)
                params={'label_selector':selector,'page':page,'per_page':50}
                if kind=='image':params['type']='snapshot'
                result=self.client.request('GET','/'+plural,params=params)
                items.extend(self.resource(kind,item) for item in result[plural])
                page=result.get('meta',{}).get('pagination',{}).get('next_page')
        return items

    def _get(self,kind,id):
        plural,singular=KINDS[kind]
        try:return self.client.request('GET',f'/{plural}/{id}')[singular]
        except Exception as exc:
            if getattr(exc,'code',None)=='not_found':return None
            raise

    def get(self,kind,id):
        item=self._get(kind,id)
        return self.resource(kind,item) if item else None

    def action(self,id):
        return self.client.request('GET',f'/actions/{id}')['action']

    def wait(self,action,seconds=120):
        deadline=time.monotonic()+seconds
        reads=Provider(self)
        while action and action['status']=='running':
            if time.monotonic()>=deadline:
                raise Infrastructure('provider action did not finish before deadline')
            time.sleep(1);action=reads.read('action',action['id'])
        if action and action['status']=='error':
            raise Infrastructure('provider action failed: '+action.get('error',{}).get('code','unknown'))

    def delete(self,item):
        current=self._get(item['kind'],item['id'])
        if current is None:return
        if current.get('labels',{}).get(PREFIX+'run')!=item['run_id']:
            raise Infrastructure(f"delete label mismatch for {item['kind']} {item['id']}")
        plural,_=KINDS[item['kind']]
        result=self.client.request('DELETE',f"/{plural}/{item['id']}")
        if result:self.wait(result.get('action'))

    def create_key(self,*,labels):
        result=self.client.request('POST','/ssh_keys',json={
            'name':labels['run_id'],'public_key':self.config['public_key'],
            'labels':self.labels(labels)})
        return self.resource('key',result['ssh_key'])

    def create_ip(self,*,labels):
        result=self.client.request('POST','/primary_ips',json={
            'name':labels['run_id'],'type':'ipv4','assignee_type':'server',
            'datacenter':self.config['datacenter'],'auto_delete':False,
            'labels':self.labels(labels)})
        self.wait(result.get('action'))
        return self.resource('ip',result['primary_ip'])

    def create_server(self,*,server_type,labels,key,ip):
        result=self.client.request('POST','/servers',json={
            'name':labels['run_id'],'server_type':server_type,'image':self.config['snapshot_id'],
            'ssh_keys':[key['id']],'location':self.config['location'],
            'public_net':{'enable_ipv4':True,'enable_ipv6':False,'ipv4':ip['id']},
            'labels':self.labels(labels)})
        # Return before waiting: the registry records the ID before SSH starts.
        return self.resource('server',result['server'])

    def server_info(self,id):
        return self.client.request('GET',f'/servers/{id}')['server']

    def pricing(self,server_type):
        result=self.client.request('GET','/pricing')['pricing']
        if result['currency']!='EUR':raise Refused('provider pricing currency must be EUR')
        types=self.client.request('GET','/server_types',params={'name':server_type})['server_types']
        if len(types)!=1:raise Refused(f'requested server type unavailable: {server_type}')
        price=next((p for p in types[0]['prices'] if p['location']==self.config['location']),None)
        if price is None:raise Refused('no price at configured location')
        ip=next((p for p in result['primary_ips'] if p['type']=='ipv4'),None)
        if ip is None:raise Refused('no IPv4 pricing')
        ip_price=next((p for p in ip['prices'] if p['location']==self.config['location']),None)
        if ip_price is None:raise Refused('no IPv4 price at configured location')
        return {'server_hourly':price['price_hourly']['gross'],
                'ip_hourly':ip_price['price_hourly']['gross'],'currency':'EUR'}
