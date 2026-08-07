FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache python3 yara
WORKDIR /app
COPY scanner.py /app/scanner.py
COPY rules /rules
RUN mkdir -p /results
ENTRYPOINT ["python3", "/app/scanner.py"]
