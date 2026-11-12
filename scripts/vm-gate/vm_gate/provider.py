"""Provider policy: bounded reads, one mutation attempt, explicit reconciliation."""
import time

from .errors import Infrastructure, Refused

TRANSIENT = {'rate_limit_exceeded', 'service_error', 'timeout', 'maintenance'}
CAPACITY = {'resource_limit_exceeded', 'resource_unavailable', 'placement_error', 'limit_exceeded'}


def code(exc):
    return getattr(exc, 'code', None) or type(exc).__name__


class Provider:
    def __init__(self, backend, event=lambda *a, **kw: None, sleep=time.sleep):
        self.backend = backend
        self.event = event
        self.sleep = sleep

    def read(self, method, *args, **kwargs):
        for attempt in range(3):
            try:
                return getattr(self.backend, method)(*args, **kwargs)
            except Exception as exc:
                name = code(exc)
                transient = name in TRANSIENT or type(exc).__name__ in {
                    'ConnectionError', 'Timeout', 'ReadTimeout', 'ConnectTimeout'}
                self.event('provider_read_error', operation=method, code=name,
                           error_type=type(exc).__name__, attempt=attempt+1)
                if not transient or attempt == 2:
                    raise Infrastructure(f'provider read {method} failed ({name})') from None
                self.sleep(attempt+1)

    def create(self, method, run_id, *args, **kwargs):
        try:
            return getattr(self.backend, method)(*args, **kwargs)
        except Exception as exc:
            name = code(exc)
            self.event('provider_create_error', operation=method, code=name,
                       error_type=type(exc).__name__)
            # No mutation retry, even if successful reconciliation finds nothing.
            resources = self.read('list', run_id)
            if name in CAPACITY:
                error = Refused(f'{kwargs.get("server_type", method)} refused: {name}')
            else:
                error = Infrastructure(f'provider create {method} uncertain/failed ({name})')
            error.resources = resources
            raise error from None

    def cleanup(self, run_id):
        owned = self.read('list', run_id)
        order = {'server': 0, 'ip': 1, 'key': 2, 'image': 3}
        failures = []
        for item in sorted(owned, key=lambda x: order[x['kind']]):
            try:
                self.backend.delete(item)
            except Exception as exc:
                failures.append((item['kind'], item['id'], code(exc)))
        remaining = []
        for item in owned:
            if self.read('get', item['kind'], item['id']) is not None:
                remaining.append((item['kind'], item['id']))
        by_label = self.read('list', run_id)
        if remaining or by_label:
            raise Infrastructure(f'cleanup resources remain for {run_id}: '
                                 f'IDs={remaining}, label_count={len(by_label)}; errors={failures}')
        # A failed DELETE response can still have completed. Exact-ID and label
        # reads above establish the result; no DELETE has been blindly repeated.
        return {'run_id': run_id, 'exact_ids_absent': True, 'labels_absent': True}

    def reap(self, now):
        expired = {}
        for item in self.read('list'):
            if item['expires'] < now:
                expired.setdefault(item['run_id'], []).append(item)
        result = []
        for run_id in sorted(expired):
            all_owned = self.read('list', run_id)
            if any(item['expires'] >= now for item in all_owned):
                raise Infrastructure(f'inconsistent expiry labels for {run_id}')
            result.append(self.cleanup(run_id))
        return result
