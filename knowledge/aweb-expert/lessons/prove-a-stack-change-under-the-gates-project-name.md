---
type: Lesson
title: Prove a stack change under the gate's project name
description: Scoped service names grow with the project name, so a test-stack change proven under a short scratch project can still fail under the default project the gate and make use; a stack certificate that put a 68-character scoped name in its common name failed only there.
tags: [lesson, testing, e2e, naapp, stack, tls]
timestamp: 2026-11-18
---

`scripts/candidate-network.py` builds a stack's scoped service hostnames
from the project name. For any project name of 23 characters or more, a
scoped name is 68 characters. An X.509 common name holds at most 64, and
`cryptography` refuses a longer one.

On 2026-11-18 the disposable stack certificate used the first service name as
its common name. A change to the test stack had been proven green on a run
whose names were 45 characters. `make -C cli e2e` then died in
`stack_tls_prepare` under its default project with "Attribute's length must
be >= 1 and <= 64, but it was 68".

# How to apply

- Prove a test-stack or naapp e2e harness change under the project name the
  gate and `make` use, not a shortened scratch name. A green under a short
  name says nothing about length limits on the gate's names.
- Disposable stack certificates carry every name in the subject alternative
  names, which is all that clients verify, and keep the common name a fixed
  short label. A TLS handshake test on a 68-character name guards this; it was
  added on the source's review branch in da1ae14aec
  (`naapp-lib/tests/test_network_certificates.py`), not yet on main at
  harvest.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-library-auth, 2026-11-18; notes/stack-scoped-names-vs-certificate-cn.md.
