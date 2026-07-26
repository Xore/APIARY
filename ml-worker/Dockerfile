FROM python:3.12-slim

LABEL maintainer="honeypot-stack"
LABEL description="ML anomaly detection worker for the honeypot stack"

WORKDIR /app

# System deps for PyTorch (CPU-only) and scipy
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Model persistence volume
VOLUME ["/models"]

# Non-root user
RUN useradd -r -s /bin/false mlworker
USER mlworker

CMD ["python", "-u", "worker.py"]
