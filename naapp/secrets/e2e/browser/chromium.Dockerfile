# Chromium for the ordinary app credential handoff, in the requester network
# namespace so the loopback callback reaches aw. The disposable CA is installed
# in NSS; TLS verification is not disabled. Playwright is pinned by naapp-lib.
FROM python:3.12-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
COPY naapp-lib/uv.lock /tmp/naapp-lib.lock
RUN playwright="$(sed -n '/^name = "playwright"$/{n;s/^version = "\(.*\)"$/\1/p;}' /tmp/naapp-lib.lock)" \
    && test -n "$playwright" \
    && uv tool install "playwright==$playwright" \
    && playwright install --with-deps chromium \
    && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/* /tmp/naapp-lib.lock \
    && chmod -R a+rX /opt/ms-playwright /opt/uv-tools
COPY naapp/secrets/e2e/browser/chromium_driver.py /driver/chromium_driver.py
RUN useradd --uid 1000 --create-home browser
ENV HOME=/home/browser
USER 1000:1000
WORKDIR /driver
ENTRYPOINT ["/opt/uv-tools/playwright/bin/python", "/driver/chromium_driver.py"]
