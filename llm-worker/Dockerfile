FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

LABEL maintainer="honeypot-stack"
LABEL description="Guarded local LLM analysis worker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin llmworker

COPY contracts.py worker.py ./

USER 10001:10001

CMD ["python", "-u", "worker.py"]
