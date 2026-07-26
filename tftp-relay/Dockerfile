FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tftp-relay .

FROM scratch
COPY --from=build /tftp-relay /tftp-relay
USER 65534:65534
EXPOSE 1069/udp
ENTRYPOINT ["/tftp-relay"]
