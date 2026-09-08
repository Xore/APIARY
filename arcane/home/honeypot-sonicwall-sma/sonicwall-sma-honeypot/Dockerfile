# SonicWall SMA1000 Work Place/AMC decoy for the CVE-2026-83548/83549
# SSRF+RCE chain (#3033) -- see main.go's own doc comment.
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /sonicwall-sma-honeypot .

FROM scratch
COPY --from=build /sonicwall-sma-honeypot /sonicwall-sma-honeypot
EXPOSE 8443
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/sonicwall-sma-honeypot", "-healthcheck"]
ENTRYPOINT ["/sonicwall-sma-honeypot"]
