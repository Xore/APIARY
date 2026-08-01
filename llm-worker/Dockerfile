FROM python:3.12-slim

LABEL maintainer="honeypot-stack"
LABEL description="Guarded local LLM analysis worker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin llmworker

COPY contracts.py worker.py ./

USER 10001:10001

CMD ["python", "-u", "worker.py"]
