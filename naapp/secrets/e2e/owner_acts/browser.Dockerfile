# The holder's browser for the H owner-acts journey. Built from the repository
# root; it carries the shared software authenticator unchanged.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates python3 py3-cryptography py3-cbor2 py3-httpx
COPY naapp-lib/testing/src/aweb_naapp_testing/webauthn.py /browser/soft_webauthn.py
COPY naapp/secrets/e2e/owner_acts/browser_driver.py /browser/browser_driver.py
RUN addgroup -g 1000 browser && adduser -D -u 1000 -G browser browser
USER 1000:1000
WORKDIR /browser
ENTRYPOINT ["python3", "/browser/browser_driver.py"]
