ARG CANDIDATE_RUNTIME
FROM ${CANDIDATE_RUNTIME}
USER root
ARG CANDIDATE_SOURCE_TREE
COPY . /opt/candidate-wheels/
RUN python3 /opt/candidate-wheels/install.py --source-tree "$CANDIDATE_SOURCE_TREE" --directory /opt/candidate-wheels \
    --python /opt/candidate-browser/server/.venv/bin/python aweb awid-service aweb-naapp
