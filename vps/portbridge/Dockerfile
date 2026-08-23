# Static Go binary in a scratch image (~5 MB).
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
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
