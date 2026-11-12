# A real Chromium for the protected round trip, driven by Playwright. It runs in
# the requester's network namespace so the page's code-less callback reaches
# aw's 127.0.0.1 loopback. TLS is verified against the lane's CA, added to the
# browser's NSS database at start; no certificate check is relaxed.
#
# Playwright, and the cryptography and cbor2 that the shared test WebAuthn
# helper needs, are the versions naapp-lib's lock pins, read from the lock at
# build time; Playwright installs the Chromium it drives. Built from the
# repository root.
FROM python:3.12-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
COPY naapp-lib/uv.lock /tmp/naapp-lib.lock
RUN locked() { sed -n "/^name = \"$1\"$/{n;s/^version = \"\(.*\)\"$/\1/p;}" /tmp/naapp-lib.lock; } \
    && playwright="$(locked playwright)" && cryptography="$(locked cryptography)" && cbor2="$(locked cbor2)" \
    && test -n "$playwright" && test -n "$cryptography" && test -n "$cbor2" \
    && uv tool install "playwright==$playwright" --with "cryptography==$cryptography" --with "cbor2==$cbor2" \
    && playwright install --with-deps chromium \
    && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/* /tmp/naapp-lib.lock \
    && chmod -R a+rX /opt/ms-playwright /opt/uv-tools
COPY naapp-lib/testing/src/aweb_naapp_testing/webauthn.py /driver/aweb_naapp_testing/webauthn.py
RUN touch /driver/aweb_naapp_testing/__init__.py
COPY naapp/secrets/e2e/protected/chromium_driver.py /driver/chromium_driver.py
WORKDIR /driver
ENTRYPOINT ["/opt/uv-tools/playwright/bin/python", "/driver/chromium_driver.py"]
