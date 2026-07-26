FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dnp3-honeypot .

FROM scratch
COPY --from=build /dnp3-honeypot /dnp3-honeypot
USER 65534:65534
EXPOSE 20000
ENTRYPOINT ["/dnp3-honeypot"]
