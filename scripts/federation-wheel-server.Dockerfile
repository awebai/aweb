# syntax=docker/dockerfile:1

# A skew runtime installs the exact selected wheel. The context contains only
# that wheel and this Dockerfile; no repository source can become a fallback.
FROM python:3.12-slim

ARG AWEB_WHEEL
ARG AWEB_WHEEL_SHA256
ARG AWEB_VERSION
ARG MCP_VERSION
ARG CANDIDATE_WHEELS=0
ARG CANDIDATE_SOURCE_TREE
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
COPY candidate-wheels /opt/candidate-wheels
RUN uv venv /opt/aweb-venv
ENV PATH="/opt/aweb-venv/bin:$PATH"

RUN groupadd --system --gid 1001 aweb \
    && useradd --system --uid 1001 --gid 1001 aweb \
    && mkdir -p /opt/aweb-wheel \
    && chown -R aweb:aweb /opt/aweb-wheel
COPY --chown=aweb:aweb ${AWEB_WHEEL} /opt/aweb-wheel/${AWEB_WHEEL}
RUN printf '%s  %s\n' "$AWEB_WHEEL_SHA256" "/opt/aweb-wheel/$AWEB_WHEEL" | sha256sum -c - \
    && if [ "$CANDIDATE_WHEELS" = 1 ]; then \
      python /opt/candidate-wheels/install.py --source-tree "$CANDIDATE_SOURCE_TREE" --directory /opt/candidate-wheels --python /opt/aweb-venv/bin/python \
        --resolve --with "mcp==$MCP_VERSION" aweb awid-service aweb-naapp; \
    else uv pip install --python /opt/aweb-venv/bin/python "mcp==$MCP_VERSION" "/opt/aweb-wheel/$AWEB_WHEEL"; fi
RUN EXPECTED="$AWEB_VERSION" MCP_EXPECTED="$MCP_VERSION" python -c 'import importlib.metadata, os; aweb = importlib.metadata.version("aweb"); mcp = importlib.metadata.version("mcp"); assert aweb == os.environ["EXPECTED"], (aweb, os.environ["EXPECTED"]); assert mcp == os.environ["MCP_EXPECTED"], (mcp, os.environ["MCP_EXPECTED"])'

ENV PYTHONUNBUFFERED=1
USER aweb
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c 'import urllib.request; urllib.request.urlopen("http://localhost:8000/health", timeout=3).read()'
ENV RELEASE_WHEEL_DIR=/opt/candidate-wheels RELEASE_WHEEL_PYTHON=/opt/aweb-venv/bin/python \
    RELEASE_WHEEL_PACKAGES="aweb awid-service aweb-naapp"
ENTRYPOINT ["sh", "-c", "if [ -f /opt/candidate-wheels/entrypoint.sh ]; then exec sh /opt/candidate-wheels/entrypoint.sh \"$@\"; else exec \"$@\"; fi", "--"]
CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]
