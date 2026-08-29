# #2619: bumped from 24.04 to 24.04.1, unblocking the freeze #2314 put
# in place. The only thing 24.04.1 changed for us is the interpreter it
# installs conpot under: the package moved from
# /usr/lib/python3.11/site-packages/conpot to
# /usr/lib/python3.12/site-packages/conpot. The package's internal
# layout below that root is unchanged (verified by diffing both images'
# conpot trees), so the six *_patch.py scripts below only needed their
# hard-coded install root repointed at python3.12.
FROM dtagdevsec/conpot:24.04.1@sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b

USER root
COPY persona_patch.py /tmp/persona_patch.py
COPY proxy_patch.py /tmp/proxy_patch.py
COPY s7comm_patch.py /tmp/s7comm_patch.py
COPY modbus_patch.py /tmp/modbus_patch.py
COPY guardian_ast_patch.py /tmp/guardian_ast_patch.py
COPY iec104_patch.py /tmp/iec104_patch.py
COPY healthcheck.py /usr/local/bin/conpot-healthcheck.py
RUN python3 /tmp/persona_patch.py && python3 /tmp/proxy_patch.py && python3 /tmp/s7comm_patch.py && python3 /tmp/modbus_patch.py && python3 /tmp/guardian_ast_patch.py && python3 /tmp/iec104_patch.py \
    && rm /tmp/persona_patch.py /tmp/proxy_patch.py /tmp/s7comm_patch.py /tmp/modbus_patch.py /tmp/guardian_ast_patch.py /tmp/iec104_patch.py \
    && chmod 755 /usr/local/bin/conpot-healthcheck.py
USER conpot
