# mushorg/redis — built from source (no published Docker Hub image)
# Mirrors the upstream docker/redis/Dockerfile from mushorg/tanner.
FROM redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2

LABEL maintainer="honeypot-stack"

# Upstream tanner redis uses a minimal read-only config.
COPY redis.conf /usr/local/etc/redis/redis.conf

USER redis
EXPOSE 6379
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
