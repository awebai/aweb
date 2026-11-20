---
type: Lesson
title: A credential-carrying TLS client trusts exactly one CA file
description: ssl.create_default_context lets SSL_CERT_FILE and SSL_CERT_DIR choose the trust roots, and SSLKEYLOGFILE record session keys outside -I, whatever an HTTP client's trust_env flag says; a client that carries a credential builds SSLContext(PROTOCOL_TLS_CLIENT), loads exactly one CA file, and proves it against a real TLS listener.
tags: [lesson, review, tls, python, credentials, testing]
timestamp: 2026-11-20
---

"The client ignores the environment" can be true for the HTTP library and
false for OpenSSL. Two reviews and a green suite of 157 tests accepted that
claim for a bearer-carrying replay client. A drill over real TLS then showed
it was false. With no CA configured and `SSL_CERT_FILE` naming a lab CA, the
client exited 0 and sent its bearer to an origin that only the environment
vouched for.

**Why.** With `cafile=None`, `ssl.create_default_context` calls
`load_default_certs`, which loads OpenSSL's default verify paths, and those
honour `SSL_CERT_FILE` and `SSL_CERT_DIR`. Unless Python runs with `-I`
(or `-E`), it also sets `keylog_filename` from `SSLKEYLOGFILE`, so the
environment can have session keys written to a file it names. httpx
`trust_env=False` stops only httpx's own environment reading (proxies, netrc
and its own certificate variables). It cannot change an `SSLContext` passed
in to it.

**The rule for review.** For any client that carries a credential
(publishers, runners, CLIs, replay tools), check how the TLS context is
built, not the client's flag:

- Build `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` and call
  `load_verify_locations` on exactly one file: the configured CA, or a pinned
  bundle such as `certifi.where()` at a locked version. Never rely on the
  default verify paths.
- A directly built context does not get the strict flags that
  `create_default_context` sets on Python 3.13+. Add `VERIFY_X509_STRICT`
  yourself (the fix also added `VERIFY_X509_PARTIAL_CHAIN`), so that
  verification is no weaker than the default. Lab certificates then need key
  identifiers: see [lab certificates need key
  identifiers](/aweb-expert/lessons/lab-certificates-need-key-identifiers.md).
- Prove it with a real TLS listener (loopback, throwaway CA). The test
  trusts the configured CA, does not trust that CA when it is named only by
  `SSL_CERT_FILE` or `SSL_CERT_DIR`, and writes no session keys. An in-memory
  transport never builds the context, so it cannot show this defect. See [a
  harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
- OpenSSL still reads `OPENSSL_CONF`, `OPENSSL_MODULES` and `OPENSSL_ENGINES`
  when it loads, before the program can act. Keeping them out of a job is
  the job environment's concern, not the client's.

**Elimination route.** The real-listener test above, written for each
credential-carrying client, is the durable guard. A lint that refuses
`create_default_context` in such clients would remove the review step. No
such lint exists yet, so until one does, a reviewer checks the construction
by hand.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-20;
notes/tls-context-trust-from-environment.md. The defect was found by the
deploy-team replay drill against provider-folders f32c6f67db. Integrations
confirmed it and withdrew its ACKs. The fix is commit 7002c2721a on the task
branch: a direct `PROTOCOL_TLS_CLIENT` context, strict flags, and the
configured CA or certifi, with loopback-TLS tests. The provider-folders seat
found the `SSLKEYLOGFILE` path. Verified at harvest: the stdlib source of
`create_default_context` (load_default_certs, the `SSLKEYLOGFILE` read
guarded by `sys.flags.ignore_environment`, and `VERIFY_X509_STRICT`). A
direct `PROTOCOL_TLS_CLIENT` context has no keylog file and no strict flag.
