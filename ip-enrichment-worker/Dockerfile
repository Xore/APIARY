# Static Go binary in a scratch image (~5 MB), same shape as portbridge/Dockerfile.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ip-enrichment-worker .

FROM scratch
COPY --from=build /ip-enrichment-worker /ip-enrichment-worker
ENTRYPOINT ["/ip-enrichment-worker"]
