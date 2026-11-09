FROM aweb-oracle-runner-tools:06e61
USER root
COPY proof.py /proof/proof.py
RUN chmod 0555 /proof/proof.py
USER 10000:10000
