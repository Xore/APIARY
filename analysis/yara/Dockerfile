FROM alpine:3.20
RUN apk add --no-cache python3 yara
WORKDIR /app
COPY scanner.py /app/scanner.py
COPY rules /rules
RUN mkdir -p /results
ENTRYPOINT ["python3", "/app/scanner.py"]
