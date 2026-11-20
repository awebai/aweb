---
type: Lesson
title: Lab certificates need key identifiers
description: Python 3.13+ verifies strictly by default and refuses a leaf without an Authority Key Identifier ("Missing Authority Key Identifier") even when openssl verify accepts it; a lab CA adds subjectKeyIdentifier, and the leaf adds subjectKeyIdentifier and authorityKeyIdentifier=keyid.
tags: [lesson, testing, tls, python, certificates]
timestamp: 2026-11-20
---

A test that needs real TLS (a stand-in server, or a loopback listener for a
client's trust test) usually makes a throwaway CA and leaf with the openssl
CLI. A pair that `openssl verify` accepts can still be refused by Python
3.13+, because `ssl.create_default_context` sets `VERIFY_X509_STRICT`. The
handshake then fails with "Missing Authority Key Identifier". The error names
the cause, but it looks like a fault in the code under test. That cost a
debugging cycle on the first TLS round-trip test.

**What to do.** Make lab material that strict verification accepts:

- CA: `-addext subjectKeyIdentifier=hash`.
- Leaf extension file: `subjectKeyIdentifier=hash` and
  `authorityKeyIdentifier=keyid`.

Do not weaken verification in the test to get past the error. A context
built directly (see [a credential-carrying TLS client trusts exactly one CA
file](/aweb-expert/lessons/a-credential-carrying-tls-client-trusts-one-ca-file.md))
should also set `VERIFY_X509_STRICT`. A lab certificate that passes is then
one that strict verification accepts.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-20;
notes/python-strict-x509-lab-certs.md. The lab CA in `deploy/standin_tls.py`
failed its first round trip until the identifiers were added.
