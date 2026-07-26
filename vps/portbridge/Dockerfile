# Static Go binary in a scratch image (~5 MB).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /portbridge .

FROM scratch
COPY --from=build /portbridge /portbridge
ENTRYPOINT ["/portbridge"]
