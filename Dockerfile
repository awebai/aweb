# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8765

# git is required because awid-service is not vendored in this repo; install it
# from the aweb repository's awid subdirectory at the commit used by this
# workspace. pgdbm is installed from PyPI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python -m pip install --upgrade pip \
    && python -m pip install \
      "awid-service @ git+https://github.com/awebai/aweb.git@d0baafa389b600c8b0a12525797d6e38726c5252#subdirectory=awid" \
      "fastapi>=0.116.1" \
      "httpx>=0.28.1" \
      "markdown>=3.8.2" \
      "nh3>=0.3.2" \
      "pgdbm==0.4.1" \
      "pyjwt[crypto]>=2.10.1" \
      "pydantic>=2.11.7" \
      "pydantic-settings>=2.10.1" \
      "pynacl>=1.6.2" \
      "uvicorn[standard]>=0.35.0"

COPY . /app/
RUN python -m pip install --no-deps .

RUN useradd --create-home --shell /usr/sbin/nologin folio
USER folio

EXPOSE 8765
CMD ["sh", "-c", "uvicorn folio.api:app --host 0.0.0.0 --port ${PORT:-8765}"]
