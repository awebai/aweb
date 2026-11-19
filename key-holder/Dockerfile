# Context: a complete wheelhouse built from the reviewed source and lock.
# The image needs neither Git credentials nor a package index at installation.
FROM python:3.12-slim
COPY . /wheels/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-index --find-links=/wheels aweb-key-holder \
    && rm -rf /wheels \
    && groupadd --gid 1001 keyholder \
    && useradd --uid 1001 --gid 1001 --create-home keyholder \
    && mkdir -p /var/lib/aweb-key-holder \
    && chown 1001:1001 /var/lib/aweb-key-holder \
    && chmod 0700 /var/lib/aweb-key-holder
USER 1001:1001
ENV PYTHONDONTWRITEBYTECODE=1
VOLUME ["/var/lib/aweb-key-holder"]
EXPOSE 8081
ENTRYPOINT ["/opt/venv/bin/aweb-key-holder", "--state", "/var/lib/aweb-key-holder/state"]
