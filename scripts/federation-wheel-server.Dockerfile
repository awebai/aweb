# syntax=docker/dockerfile:1

# A skew runtime installs the exact selected wheel. The context contains only
# that wheel and this Dockerfile; no repository source can become a fallback.
FROM python:3.12-slim

ARG AWEB_WHEEL
ARG AWEB_WHEEL_SHA256
ARG AWEB_VERSION
ARG MCP_VERSION

RUN groupadd --system --gid 1001 aweb \
    && useradd --system --uid 1001 --gid 1001 aweb \
    && mkdir -p /opt/aweb-wheel \
    && chown -R aweb:aweb /opt/aweb-wheel
COPY --chown=aweb:aweb ${AWEB_WHEEL} /opt/aweb-wheel/${AWEB_WHEEL}
RUN printf '%s  %s\n' "$AWEB_WHEEL_SHA256" "/opt/aweb-wheel/$AWEB_WHEEL" | sha256sum -c - \
    && pip install --no-cache-dir "mcp==$MCP_VERSION" "/opt/aweb-wheel/$AWEB_WHEEL" \
    && EXPECTED="$AWEB_VERSION" MCP_EXPECTED="$MCP_VERSION" python -c 'import importlib.metadata, os; aweb = importlib.metadata.version("aweb"); mcp = importlib.metadata.version("mcp"); assert aweb == os.environ["EXPECTED"], (aweb, os.environ["EXPECTED"]); assert mcp == os.environ["MCP_EXPECTED"], (mcp, os.environ["MCP_EXPECTED"])'

ENV PYTHONUNBUFFERED=1
USER aweb
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c 'import urllib.request; urllib.request.urlopen("http://localhost:8000/health", timeout=3).read()'
CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]
