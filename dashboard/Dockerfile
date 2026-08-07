# dashboard — multi-stage Go build
# Reads honeypot JSON logs from /logs and serves a live analysis UI.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY static ./static
COPY ui ./ui
COPY assets_pdf ./assets_pdf
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags "-s -w" -o /dashboard .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /dashboard /usr/local/bin/dashboard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dashboard"]
