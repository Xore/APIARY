FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

LABEL maintainer="honeypot-stack"
LABEL description="Guarded local LLM analysis worker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin llmworker

COPY contracts.py worker.py ./

USER 10001:10001

CMD ["python", "-u", "worker.py"]
