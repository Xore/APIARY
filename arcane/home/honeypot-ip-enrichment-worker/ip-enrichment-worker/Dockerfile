# Static Go binary in a scratch image (~5 MB), same shape as portbridge/Dockerfile.
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ip-enrichment-worker .

FROM scratch
COPY --from=build /ip-enrichment-worker /ip-enrichment-worker
ENTRYPOINT ["/ip-enrichment-worker"]
