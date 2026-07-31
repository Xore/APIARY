FROM dtagdevsec/conpot:24.04

USER root
COPY persona_patch.py /tmp/persona_patch.py
COPY proxy_patch.py /tmp/proxy_patch.py
COPY healthcheck.py /usr/local/bin/conpot-healthcheck.py
RUN python3 /tmp/persona_patch.py && python3 /tmp/proxy_patch.py \
    && rm /tmp/persona_patch.py /tmp/proxy_patch.py \
    && chmod 755 /usr/local/bin/conpot-healthcheck.py
USER conpot
