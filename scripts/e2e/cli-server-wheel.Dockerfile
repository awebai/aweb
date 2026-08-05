FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY *.whl /opt/aweb-artifact/
RUN python -m pip install --no-cache-dir /opt/aweb-artifact/*.whl

RUN groupadd --system --gid 1001 aweb \
    && useradd --system --uid 1001 --gid 1001 aweb

WORKDIR /app
ENV PYTHONUNBUFFERED=1
USER aweb
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]
