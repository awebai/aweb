# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.13.7 AS uv
FROM docker:27-cli AS docker
FROM python:3.13-slim-bookworm
COPY --from=uv /uv /usr/local/bin/uv
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
ENV UV_HTTP_TIMEOUT=300 UV_CONCURRENT_DOWNLOADS=4 PLAYWRIGHT_BROWSERS_PATH=/opt/browsers UV_PYTHON=/usr/local/bin/python3.13 UV_PYTHON_DOWNLOADS=never
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools ca-certificates dbus gnome-keyring && rm -rf /var/lib/apt/lists/*
COPY approval /source/approval
COPY holder /source/holder
COPY runner-requirements.txt /runner-requirements.txt
RUN umask 022 && uv build --no-sources --wheel --out-dir /wheels /source/holder/awid \
 && uv build --no-sources --wheel --out-dir /wheels /source/approval \
 && uv build --no-sources --wheel --out-dir /wheels /source/holder/key-holder \
 && uv export --project /source/holder/key-holder --frozen --no-dev --no-emit-project --no-emit-package awid-service --no-emit-package aweb-approval-service -o /wheels/runtime-requirements.txt \
 && uv venv --python /usr/local/bin/python3.13 /opt/venv \
 && uv pip install --python /opt/venv/bin/python --require-hashes -r /wheels/runtime-requirements.txt \
 && uv pip install --python /opt/venv/bin/python --no-deps /wheels/*.whl \
 && uv pip install --python /opt/venv/bin/python --require-hashes --no-deps -r /runner-requirements.txt \
 && /opt/venv/bin/python -m playwright install --with-deps chromium \
 && uv pip check --python /opt/venv/bin/python \
 && uv pip freeze --python /opt/venv/bin/python > /package-inventory.txt \
 && sha256sum /wheels/*.whl > /wheel-hashes.txt \
 && chmod -R a+rX /opt/venv /opt/browsers \
 && rm -rf /source
COPY fixture-ca.crt /usr/local/share/ca-certificates/adcl6-fixture.crt
RUN update-ca-certificates && /opt/venv/bin/python -c "import certifi; from pathlib import Path; p=Path(certifi.where()); p.write_bytes(p.read_bytes()+Path('/usr/local/share/ca-certificates/adcl6-fixture.crt').read_bytes())"
ENV PATH=/opt/venv/bin:$PATH
COPY aw /usr/local/bin/aw
COPY journey.py /journey.py
