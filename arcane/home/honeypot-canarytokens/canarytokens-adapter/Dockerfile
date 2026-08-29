# canarytokens-adapter -- #1426: this repo's own small webhook receiver,
# not a vendored tool (nothing to vendor: translating an arbitrary JSON
# webhook into this repo's shared sensor-log shape is a few dozen lines,
# not a project). Matches rdp-honeypot/Dockerfile's own scratch-based shape.
FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /canarytokens-adapter .

FROM scratch
COPY --from=build /canarytokens-adapter /canarytokens-adapter
EXPOSE 8090
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/canarytokens-adapter", "-healthcheck"]
ENTRYPOINT ["/canarytokens-adapter"]
