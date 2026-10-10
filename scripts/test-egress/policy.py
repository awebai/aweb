"""Reviewed test-only destinations. Exceptions still never reach a public host."""
import json
from pathlib import Path

# One reviewed entry. HTTPS CONNECT is refused; its inner method is unknowable.
# The refusal, not method attribution, guarantees no production access.
# Another test attempting an HTTPS write to app.aweb.ai is reported but does
# NOT fail natively. This is acceptable only because CONNECT never opens.
DENIED_READS = json.loads(Path(__file__).with_name('denied-reads.json').read_text())


def reserved(host):
    host = (host or '').lower().rstrip('.')
    return host == 'localhost' or host.endswith(('.localhost', '.example', '.invalid', '.test'))


def denied_read(host, method):
    return any(item['host'] == host and item['method'] == method for item in DENIED_READS)
