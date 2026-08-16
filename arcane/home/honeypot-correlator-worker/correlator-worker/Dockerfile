# Static Go binary in a scratch image (~5 MB), same shape as ip-enrichment-worker/Dockerfile.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /correlator-worker .

FROM scratch
COPY --from=build /correlator-worker /correlator-worker
ENTRYPOINT ["/correlator-worker"]
