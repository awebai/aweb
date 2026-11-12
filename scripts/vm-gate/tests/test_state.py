import tempfile
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from threading import Barrier

from vm_gate.state import Store
from vm_gate.errors import Refused, Infrastructure

class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'state.sqlite3'
        self.store=lambda *args,**kw:Store(self.path,*args,clock=lambda:10,**kw)

    def test_reservation_counts_before_provider_create(self):
        s=self.store(5,seed_eur=2)
        s.reserve('one',2,now=10,expires=1000)
        with self.assertRaisesRegex(Refused,'cap'):
            s.reserve('two',2,now=10,expires=1000)
        self.assertEqual(Decimal(s.totals(now=10)['reserved']),2)

    def test_parallel_process_views_cannot_oversubscribe(self):
        self.store(3)
        barrier=Barrier(8)
        def attempt(i):
            s=self.store(3);barrier.wait()
            try:s.reserve(str(i),1,now=10,expires=1000);return True
            except Refused:return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted=list(pool.map(attempt,range(8)))
        self.assertEqual(sum(accepted),3,'concurrent admission crossed the cap')
        self.assertEqual(Decimal(self.store(3).totals(now=10)['reserved']),3)

    def test_settlement_releases_unused_reserve_but_keeps_actual(self):
        s=self.store(5);s.reserve('one',4,now=10,expires=1000);s.settle('one','1.25',now=20)
        s.reserve('two',3,now=30,expires=1000)
        totals=s.totals(now=30)
        self.assertEqual(Decimal(totals['settled']),Decimal('1.25'))
        self.assertEqual(Decimal(totals['reserved']),3)
        self.assertEqual(s.get('one')['actual'],'1.250000')

    def test_daily_warning_includes_outstanding_reservations(self):
        s=self.store(100,daily_warning_eur=20)
        s.reserve('one',19,now=10,expires=1000);self.assertFalse(s.totals(now=10)['warn'])
        s.reserve('two',1,now=10,expires=1000);self.assertTrue(s.totals(now=10)['warn'])
        s.settle('one',1,now=10);s.settle('two',1,now=10)
        self.assertFalse(s.totals(now=10)['warn'])
        self.assertFalse(s.totals(now=86410)['warn'])

    def test_expiry_and_updates_are_isolated_by_run(self):
        s=self.store(10)
        s.reserve('old',1,owner='owner-a',sha='a'*40,expires=20,now=10)
        s.reserve('live',1,owner='owner-b',sha='b'*40,expires=100,now=10)
        s.update('old',{'server_id':11,'phase':'running'})
        self.assertEqual([r['run_id'] for r in s.expired(21)],['old'])
        self.assertEqual(s.get('old')['server_id'],11)
        self.assertNotIn('server_id',s.get('live'))
        s.settle('old',1,now=21)
        self.assertEqual(s.expired(21),[])

    def test_outstanding_reserve_warns_after_day_rollover(self):
        s=self.store(100,daily_warning_eur=20)
        s.reserve('long',20,now=10,expires=200000)
        self.assertTrue(s.totals(now=86410)['warn'])

    def test_registry_identity_cannot_be_overwritten_by_progress(self):
        s=self.store(10);s.reserve('one',1,sha='a'*40,expires=1000)
        with self.assertRaisesRegex(Refused,'immutable'):
            s.update('one',{'sha':'b'*40})
        self.assertEqual(s.get('one')['sha'],'a'*40)

    def test_invalid_money_refuses_without_a_database_change(self):
        with self.assertRaisesRegex(Refused,'money'):
            self.store('not-money')

    def test_reservation_requires_a_future_expiry(self):
        s=self.store(10)
        with self.assertRaisesRegex(Refused,'expiry'):
            s.reserve('missing',1)
        with self.assertRaisesRegex(Refused,'expiry'):
            s.reserve('past',1,expires=5)
        self.assertIsNone(s.get('missing'));self.assertIsNone(s.get('past'))

    def test_default_reservation_time_uses_the_injected_clock(self):
        s=self.store(10);s.reserve('one',1,expires=100)
        self.assertEqual(s.get('one')['created'],10)

    def test_initial_schema_has_an_ordered_version(self):
        self.store(10)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],1)

    def test_newer_schema_is_refused(self):
        with sqlite3.connect(self.path) as db:db.execute('PRAGMA user_version=99')
        with self.assertRaisesRegex(Infrastructure,'schema'):
            self.store(10)

    def test_negative_money_refuses(self):
        s=self.store(10)
        with self.assertRaisesRegex(Refused,'negative'):
            s.reserve('bad',-1,expires=1000)

if __name__=='__main__':unittest.main()
