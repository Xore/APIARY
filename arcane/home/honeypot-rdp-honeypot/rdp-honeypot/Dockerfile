# RDP (3389/tcp) decoy, Go port of CommunityHoneyNetwork/rdphoney (#238,
# #412) -- see main.go's own doc comment for why this is genuinely simple
# despite RDP's reputation, and why that reverses #238's original "vendor,
# don't port" call.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /rdp-honeypot .

FROM scratch
COPY --from=build /rdp-honeypot /rdp-honeypot
EXPOSE 3389
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/rdp-honeypot", "-healthcheck"]
ENTRYPOINT ["/rdp-honeypot"]
