FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

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
