# mushorg/phpox — PHP sandbox for tanner (no published Docker Hub image)
# Provides the PHP eval sandbox tanner uses for template-injection emulation.
FROM php:8.2-cli-alpine@sha256:6d3dcc922fa36d06d6eefba5697a0aee599cf2f306b3cc2700a6526bc8fd5c09

LABEL maintainer="honeypot-stack"

RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/mushorg/phpox /opt/phpox

WORKDIR /opt/phpox
EXPOSE 8088
CMD ["php", "-S", "0.0.0.0:8088", "index.php"]
