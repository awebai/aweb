# A real Chromium for the protected round trip, driven by Playwright. It runs in
# the requester's network namespace so the page's code-less callback reaches
# aw's 127.0.0.1 loopback. TLS is verified against the lane's CA, added to the
# browser's NSS database at start; no certificate check is relaxed.
FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools && rm -rf /var/lib/apt/lists/*
COPY naapp/secrets/e2e/protected/chromium_driver.py /driver/chromium_driver.py
WORKDIR /driver
ENTRYPOINT ["python3", "/driver/chromium_driver.py"]
