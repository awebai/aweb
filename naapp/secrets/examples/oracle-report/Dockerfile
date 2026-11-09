FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
COPY requirements.txt /opt/report/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/report/requirements.txt
COPY report.py /opt/report/report.py
WORKDIR /opt/report
# The runner replaces image defaults with the complete pinned job argv/env/cwd.
ENTRYPOINT ["/usr/local/bin/python", "-I", "-B", "/opt/report/report.py"]
