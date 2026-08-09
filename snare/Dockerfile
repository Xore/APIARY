# Build mushorg/snare from source with a deterministic fictional portal.
FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

RUN apt-get update && apt-get install -y --no-install-recommends \
        git wget libxml2-dev libxslt-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/snare

ARG SNARE_REF=b17fdfe7c2ba3ac540548763d73fc475cfc185c4
RUN git clone https://github.com/mushorg/snare.git . \
 && git checkout "$SNARE_REF" \
 && rm -rf .git

COPY compatibility_patch.py /tmp/snare-compatibility-patch.py
RUN python /tmp/snare-compatibility-patch.py \
 && rm /tmp/snare-compatibility-patch.py

RUN pip install --no-cache-dir -U pip setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir 'aiohttp==3.8.6' \
 && python setup.py install

ARG PAGE_URL=portal.meridian.example
ARG TANNER=tanner
ARG PORT=8080
ENV PAGE_URL=${PAGE_URL} TANNER=${TANNER} PORT=${PORT}

# Emit SNARE's content-addressed page layout without cloning a real company.
COPY persona /tmp/persona
COPY build_persona.py /tmp/build-persona.py
RUN python /tmp/build-persona.py \
 && mkdir -p /opt/snare/pages \
 && cp -a /opt/persona-pages/. /opt/snare/pages/ \
 && rm -rf /tmp/persona /tmp/build-persona.py

COPY entrypoint.sh /usr/local/bin/snare-entry.sh
RUN chmod +x /usr/local/bin/snare-entry.sh

VOLUME ["/opt/snare/pages"]
EXPOSE ${PORT}
CMD ["/usr/local/bin/snare-entry.sh"]
