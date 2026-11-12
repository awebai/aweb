"""Exit-code authority for vm-gate.

Normal gate exits are passed through and identified by summary.infrastructure=null.
Refusal (78) means local/provider admission rejected the requested work.
Infrastructure failure (70) means a gate verdict could not be delivered safely.
A summary always carries classification, including for a gate that itself uses
one of these numeric codes. Infrastructure can never be reported as success.
"""
from enum import IntEnum

class Exit(IntEnum):
    INFRASTRUCTURE = 70
    REFUSED = 78

class Refused(Exception):
    classification = 'refused'
    exit_code = Exit.REFUSED

class Infrastructure(Exception):
    classification = 'infrastructure'
    exit_code = Exit.INFRASTRUCTURE
