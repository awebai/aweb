"""Read the real team's grant with the deployment's purpose-bound app key."""
import json
from pathlib import Path
import sys
import urllib.request

from awid.did import did_key_from_signing_key
from aweb_naapp.runtime.app_credentials import AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.signing_key import parse_signing_key_hex

key = parse_signing_key_hex(Path('/fixture/tls/grant-read.key').read_text().strip())
signer = AppCredentialSigner(app_id='folio', purpose='app-grant-read', key=AppKey(
    kid='folio:grant-read-1', did_key=did_key_from_signing_key(bytes(key)), signing_key=key))
target = 'https://folio-wakes.test:38000/v1/apps/self/grant'
request = urllib.request.Request(target, headers=signer.sign(method='GET', target=target, team_id=sys.argv[1]).headers)
with urllib.request.urlopen(request, timeout=10) as response:
    body = json.load(response)
    # Only lifecycle evidence; never emit credentials or request headers.
    print(json.dumps({k: body[k] for k in ('state', 'installation_id', 'generation', 'granted_scopes', 'max_age_seconds', 'installed_at')}))
