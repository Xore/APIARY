# mushorg/redis — built from source (no published Docker Hub image)
# Mirrors the upstream docker/redis/Dockerfile from mushorg/tanner.
FROM redis:7-alpine

LABEL maintainer="honeypot-stack"

# Upstream tanner redis uses a minimal read-only config.
COPY redis.conf /usr/local/etc/redis/redis.conf

USER redis
EXPOSE 6379
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
