FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

LABEL maintainer="honeypot-stack"
LABEL description="#154 phase 5: correlates real sensor events into campaigns and scores them against deterministic criticality rules"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# decode_correlate.py/campaign_correlator.py/criticality_rules.py are the
# same, unmodified modules already proven against corpus.jsonl in CI (see
# tests/) -- this container runs the exact code that testing already
# covers, not a copy or a reimplementation.
COPY decode_correlate.py campaign_correlator.py criticality_rules.py worker.py .

CMD ["python", "-u", "worker.py"]
