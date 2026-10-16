"""Reviewed test-only destinations. Exceptions still never reach a public host."""
import json
from pathlib import Path

# No production destination currently has an exception.
DENIED_READS = json.loads(Path(__file__).with_name('denied-reads.json').read_text())


def reserved(host):
    host = (host or '').lower().rstrip('.')
    return host == 'localhost' or host.endswith(('.localhost', '.example', '.invalid', '.test'))


def denied_read(host, method):
    return any(item['host'] == host and item['method'] == method for item in DENIED_READS)
