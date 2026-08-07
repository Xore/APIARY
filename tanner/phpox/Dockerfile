# mushorg/phpox — PHP sandbox for tanner (no published Docker Hub image)
# Provides the PHP eval sandbox tanner uses for template-injection emulation.
FROM php:8.5-cli-alpine@sha256:0554eb53778b5316f6b9a3447c9dfa3cf2141c0c02ff816c42cdc9aa240a34aa

LABEL maintainer="honeypot-stack"

RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/mushorg/phpox /opt/phpox

WORKDIR /opt/phpox
EXPOSE 8088
CMD ["php", "-S", "0.0.0.0:8088", "index.php"]
