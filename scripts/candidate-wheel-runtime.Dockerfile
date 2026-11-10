ARG CANDIDATE_RUNTIME
FROM ${CANDIDATE_RUNTIME}
USER root
COPY . /opt/candidate-wheels/
RUN python3 /opt/candidate-wheels/install.py --directory /opt/candidate-wheels \
    --python /opt/candidate-browser/server/.venv/bin/python aweb awid-service aweb-naapp
