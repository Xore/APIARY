FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /endlessh-honeypot .

FROM scratch
COPY --from=build /endlessh-honeypot /endlessh-honeypot
USER 65534:65534
EXPOSE 2222
ENTRYPOINT ["/endlessh-honeypot"]
