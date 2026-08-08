# mushorg/phpox — PHP sandbox for tanner (no published Docker Hub image)
# Provides the PHP eval sandbox tanner uses for template-injection emulation.
FROM php:8.5-cli-alpine@sha256:0554eb53778b5316f6b9a3447c9dfa3cf2141c0c02ff816c42cdc9aa240a34aa

LABEL maintainer="honeypot-stack"

RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/mushorg/phpox /opt/phpox

# #877: this is the PHP eval sandbox that actually executes
# attacker-influenced php_code_injection/php_object_injection/
# template_injection payloads tanner routes to it -- it ran as root (uid 0)
# by default, with nothing in this file or docker-compose.tanner.yml's
# service definition dropping to a real unprivileged user (cap_drop: ALL,
# no-new-privileges, and read_only: true there are all real, complementary
# hardening, but none of them make the process's own uid non-root). `php -S`
# only ever needs to read /opt/phpox and write to the /tmp tmpfs the compose
# file already provides -- no reason for the eval sandbox to hold uid 0.
RUN addgroup -S phpox && adduser -S -G phpox phpox \
 && chown -R phpox:phpox /opt/phpox
USER phpox

WORKDIR /opt/phpox
EXPOSE 8088
CMD ["php", "-S", "0.0.0.0:8088", "index.php"]
