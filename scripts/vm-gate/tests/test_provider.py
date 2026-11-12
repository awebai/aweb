import unittest
from vm_gate.provider import Provider
from vm_gate.errors import Infrastructure, Refused

class APIError(Exception):
    def __init__(self,code):self.code=code

class FakeBackend:
    def __init__(self):
        self.calls=[];self.outcomes=[];self.items=[];self.deleted=[]
    def list(self,run_id=None):
        self.calls.append(('list',run_id))
        if self.outcomes:
            item=self.outcomes.pop(0)
            if isinstance(item,Exception):raise item
        return [dict(x) for x in self.items if run_id is None or x['run_id']==run_id]
    def get(self,kind,id):
        self.calls.append(('get',kind,id))
        return next((dict(x) for x in self.items if x['kind']==kind and x['id']==id),None)
    def create_server(self,**kwargs):
        self.calls.append(('create',kwargs));item=self.outcomes.pop(0)
        if isinstance(item,Exception):raise item
        return item
    def delete(self,item):
        self.deleted.append((item['kind'],item['id']))
        self.items=[x for x in self.items if (x['kind'],x['id'])!=(item['kind'],item['id'])]

def resource(kind,id,run='old',expires=5):
    return {'kind':kind,'id':id,'run_id':run,'expires':expires,'owner':'seat','sha':'a'*40}

class ProviderTests(unittest.TestCase):
    def test_reads_retry_transient_failure_only_three_attempts(self):
        b=FakeBackend();b.outcomes=[APIError('service_error')]*4
        with self.assertRaises(Infrastructure):Provider(b,sleep=lambda _:None).read('list')
        self.assertEqual(len(b.calls),3)

    def test_permanent_read_failure_is_not_an_empty_inventory(self):
        b=FakeBackend();b.outcomes=[APIError('forbidden')]
        with self.assertRaises(Infrastructure):Provider(b,sleep=lambda _:None).read('list')
        self.assertEqual(len(b.calls),1)

    def test_capacity_refuses_once_names_type_and_code(self):
        b=FakeBackend();b.outcomes=[APIError('resource_limit_exceeded')]
        with self.assertRaises(Refused) as got:
            Provider(b,sleep=lambda _:None).create('create_server','r',server_type='ccx43')
        self.assertIn('ccx43',str(got.exception));self.assertIn('resource_limit_exceeded',str(got.exception))
        self.assertEqual(sum(x[0]=='create' for x in b.calls),1)

    def test_uncertain_create_reconciles_labels_and_never_repeats(self):
        b=FakeBackend();b.outcomes=[APIError('timeout')];b.items=[resource('server',11,run='r')]
        with self.assertRaises(Infrastructure) as got:
            Provider(b,sleep=lambda _:None).create('create_server','r',server_type='ccx33')
        self.assertEqual(sum(x[0]=='create' for x in b.calls),1)
        self.assertIn(('list','r'),b.calls)
        self.assertEqual(got.exception.resources[0]['id'],11)

    def test_cleanup_only_owned_ids_and_verifies_absence(self):
        b=FakeBackend();b.items=[resource('server',1),resource('ip',2),resource('key',3),resource('server',4,run='live',expires=100)]
        Provider(b,sleep=lambda _:None).cleanup('old')
        self.assertEqual(b.deleted,[('server',1),('ip',2),('key',3)])
        self.assertEqual([x['id'] for x in b.items],[4])
        self.assertEqual(b.calls[-1],('list','old'))

    def test_cleanup_verifies_exact_id_even_if_label_disappears(self):
        b=FakeBackend();b.items=[resource('ip',2)]
        def wrong_delete(item):b.items[0]['run_id']='other'
        b.delete=wrong_delete
        with self.assertRaisesRegex(Infrastructure,'remain'):
            Provider(b,sleep=lambda _:None).cleanup('old')

    def test_reaper_preserves_unexpired_neighbor(self):
        b=FakeBackend();b.items=[resource('server',1),resource('ip',2),resource('key',3),resource('server',4,run='live',expires=100)]
        Provider(b,sleep=lambda _:None).reap(10)
        self.assertEqual([x['id'] for x in b.items],[4])

if __name__=='__main__':unittest.main()
