# A real Chromium for the protected round trip, driven by Playwright. It runs in
# the requester's network namespace so the page's code-less callback reaches
# aw's 127.0.0.1 loopback. TLS is verified against the lane's CA, added to the
# browser's NSS database at start; no certificate check is relaxed.
#
# Playwright is the version naapp-lib's lock pins, read from the lock at build
# time, and installs the Chromium that version drives. Built from the
# repository root.
FROM python:3.12-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
COPY naapp-lib/uv.lock /tmp/naapp-lib.lock
RUN version="$(sed -n '/^name = "playwright"$/{n;s/^version = "\(.*\)"$/\1/p;}' /tmp/naapp-lib.lock)" \
    && test -n "$version" \
    && uv tool install "playwright==$version" \
    && playwright install --with-deps chromium \
    && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/* /tmp/naapp-lib.lock \
    && chmod -R a+rX /opt/ms-playwright /opt/uv-tools
COPY naapp/secrets/e2e/protected/chromium_driver.py /driver/chromium_driver.py
WORKDIR /driver
ENTRYPOINT ["/opt/uv-tools/playwright/bin/python", "/driver/chromium_driver.py"]
