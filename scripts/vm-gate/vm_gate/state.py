"""SQLite registry and conservative spend reservations, shared by local workers."""
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import json
from pathlib import Path
import sqlite3
import time

from .errors import Infrastructure, Refused

MICRO = Decimal(1_000_000)


def money(value):
    try:
        value = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise Refused('invalid money amount') from None
    if not value.is_finite() or value < 0:
        raise Refused('negative or non-finite money is invalid')
    return int((value * MICRO).to_integral_value(rounding=ROUND_CEILING))


def euros(value):
    return f'{Decimal(value) / MICRO:.6f}'


class Store:
    def __init__(self, path, cap_eur, daily_warning_eur=20, seed_eur=0, clock=None):
        self.clock = clock or time.time
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cap = money(cap_eur)
        self.warning = money(daily_warning_eur)
        with self._db() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            migrations = sorted(Path(__file__).with_name('migrations').glob('*.sql'))
            if version > len(migrations):
                raise Infrastructure(f'unsupported registry schema {version}')
            for index, migration in enumerate(migrations, 1):
                if index <= version:
                    continue
                statement = ''
                for line in migration.read_text().splitlines(keepends=True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        db.execute(statement)
                        statement = ''
                if statement.strip():
                    raise Infrastructure(f'incomplete registry migration {migration.name}')
                db.execute(f'PRAGMA user_version={index}')
            db.execute('INSERT OR IGNORE INTO meta VALUES (?,?)', ('seed', str(money(seed_eur))))
        self.path.chmod(0o600)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.execute('COMMIT')
        except Exception:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    @staticmethod
    def _total(db):
        seed = int(db.execute("SELECT value FROM meta WHERE key='seed'").fetchone()[0])
        settled, reserved = db.execute('''SELECT
            COALESCE(SUM(CASE WHEN settled IS NOT NULL THEN actual ELSE 0 END),0),
            COALESCE(SUM(CASE WHEN settled IS NULL THEN reserved ELSE 0 END),0)
            FROM runs''').fetchone()
        return seed + settled, reserved

    def reserve(self, run_id, amount, *, owner='seat', sha='a'*40, expires=None, now=None):
        amount = money(amount)
        now = self.clock() if now is None else now
        if expires is None or expires <= now:
            raise Refused('a future expiry is required for a reservation')
        with self._db() as db:
            settled, reserved = self._total(db)
            if settled + reserved + amount > self.cap:
                raise Refused(f'spend cap refused: {euros(settled+reserved+amount)} > {euros(self.cap)} EUR')
            try:
                db.execute('INSERT INTO runs(run_id,owner,sha,created,expires,reserved) VALUES (?,?,?,?,?,?)',
                           (run_id, owner, sha, now, expires, amount))
            except sqlite3.IntegrityError:
                raise Refused(f'run already reserved: {run_id}') from None

    def settle(self, run_id, actual, *, now=None):
        now = self.clock() if now is None else now
        actual = money(actual)
        with self._db() as db:
            row = db.execute('SELECT actual,settled FROM runs WHERE run_id=?', (run_id,)).fetchone()
            if row is None:
                raise Infrastructure(f'unknown spend reservation: {run_id}')
            if row['settled'] is not None:
                if row['actual'] != actual:
                    raise Infrastructure(f'conflicting settlement: {run_id}')
                return
            db.execute('UPDATE runs SET actual=?,settled=? WHERE run_id=?', (actual, now, run_id))

    def totals(self, *, now=None):
        now = self.clock() if now is None else now
        start = int(now // 86400) * 86400
        with self._db() as db:
            settled, reserved = self._total(db)
            daily = db.execute('''SELECT COALESCE(SUM(CASE WHEN settled IS NULL
                THEN reserved ELSE actual END),0) FROM runs
                WHERE settled IS NULL OR (settled>=? AND settled<?)''',
                               (start, start+86400)).fetchone()[0]
            return {'settled': euros(settled), 'reserved': euros(reserved),
                    'daily': euros(daily), 'warn': daily >= self.warning,
                    'cap': euros(self.cap)}

    @staticmethod
    def _row(row):
        if row is None:
            return None
        result = dict(row)
        result.update(json.loads(result.pop('payload')))
        result['reserved'] = euros(result['reserved'])
        result['actual'] = euros(result['actual']) if result['actual'] is not None else None
        return result

    def get(self, run_id):
        with self._db() as db:
            return self._row(db.execute('SELECT * FROM runs WHERE run_id=?', (run_id,)).fetchone())

    def update(self, run_id, patch):
        immutable = {'run_id','owner','sha','created','expires','reserved','actual','settled','payload'}
        if immutable.intersection(patch):
            raise Refused('registry identity and spend fields are immutable progress data')
        with self._db() as db:
            row = db.execute('SELECT payload FROM runs WHERE run_id=?', (run_id,)).fetchone()
            if row is None:
                raise Infrastructure(f'unknown run: {run_id}')
            data = json.loads(row[0])
            data.update(patch)
            db.execute('UPDATE runs SET payload=? WHERE run_id=?', (json.dumps(data), run_id))

    def expired(self, now):
        with self._db() as db:
            return [self._row(row) for row in db.execute(
                'SELECT * FROM runs WHERE settled IS NULL AND expires<=? ORDER BY created,run_id', (now,))]

    def runs(self):
        with self._db() as db:
            return [self._row(row) for row in db.execute('SELECT * FROM runs ORDER BY created DESC,run_id')]
