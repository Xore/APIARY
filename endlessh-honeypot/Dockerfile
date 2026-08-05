FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /endlessh-honeypot .

FROM scratch
COPY --from=build /endlessh-honeypot /endlessh-honeypot
USER 65534:65534
EXPOSE 2222
ENTRYPOINT ["/endlessh-honeypot"]
