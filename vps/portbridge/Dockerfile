# Static Go binary in a scratch image (~5 MB).
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod .
# Every non-test .go file, not a hand-maintained list. The enumerated form
# silently omitted community_id.go when it was added: `go build ./...` locally
# compiles the whole directory and passed, while the image build failed on
# undefined symbols. A list that has to be updated in lockstep with the
# package is a list that will be wrong again.
COPY *.go ./
RUN rm -f ./*_test.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /portbridge .

FROM scratch
COPY --from=build /portbridge /portbridge
ENTRYPOINT ["/portbridge"]
