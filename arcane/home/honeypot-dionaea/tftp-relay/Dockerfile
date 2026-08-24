FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tftp-relay .

FROM scratch
COPY --from=build /tftp-relay /tftp-relay
USER 65534:65534
EXPOSE 1069/udp
ENTRYPOINT ["/tftp-relay"]
