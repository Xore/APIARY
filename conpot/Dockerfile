FROM dtagdevsec/conpot:24.04

USER root
COPY persona_patch.py /tmp/persona_patch.py
COPY proxy_patch.py /tmp/proxy_patch.py
RUN python3 /tmp/persona_patch.py && python3 /tmp/proxy_patch.py \
    && rm /tmp/persona_patch.py /tmp/proxy_patch.py
USER conpot
