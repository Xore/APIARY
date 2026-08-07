# Citrix ADC/NetScaler Gateway decoy (CVE-2019-19781), Go port of
# t3chn0m4g3/CitrixHoneypot (#238, #414) -- see main.go's own doc comment.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /citrix-honeypot .

FROM scratch
COPY --from=build /citrix-honeypot /citrix-honeypot
EXPOSE 443
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/citrix-honeypot", "-healthcheck"]
ENTRYPOINT ["/citrix-honeypot"]
