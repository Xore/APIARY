# canarytokens-http-router -- this repo's own code, not vendored (see
# main.go's own package doc for why this exists). Matches
# canarytokens-adapter/Dockerfile's own scratch-based shape exactly --
# zero third-party dependencies (redisHGetAll speaks just enough RESP by
# hand), same build/runtime split.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /canarytokens-http-router .

FROM scratch
COPY --from=build /canarytokens-http-router /canarytokens-http-router
EXPOSE 8083
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/canarytokens-http-router", "-healthcheck"]
ENTRYPOINT ["/canarytokens-http-router"]
