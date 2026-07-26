# dashboard — multi-stage Go build
# Reads honeypot JSON logs from /logs and serves a live analysis UI.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY static ./static
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags "-s -w" -o /dashboard .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /dashboard /usr/local/bin/dashboard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dashboard"]
