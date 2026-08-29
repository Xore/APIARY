# #2314: dtagdevsec/conpot:24.04 is pinned to a specific manifest-list
# digest, deliberately NOT bumped to 24.04.1 even though one exists.
# The six *_patch.py scripts below hard-code
# /usr/lib/python3.11/site-packages/conpot/templates/default, which is
# 24.04's directory layout; 24.04.1 restructured the package and the
# patches FileNotFoundError at build time. Bumping requires auditing
# every patch script against the 24.04.1 layout -- tracked separately.
FROM dtagdevsec/conpot:24.04@sha256:717f0bdf79ad267e7402ff09fcc2f4ce413e9165843dd58c18f340acdd49ea7e

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
