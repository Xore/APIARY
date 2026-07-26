FROM busybox:1.36 AS command_rootfs

FROM alpine:3.20 AS template_rootfs
RUN apk add --no-cache python3 py3-jinja2 py3-mako py3-tornado

FROM docker:27-dind

# Seed both emulator images without giving the nested daemon internet access.
COPY --from=command_rootfs / /seed/command-rootfs/
COPY --from=template_rootfs / /seed/template-rootfs/
COPY entrypoint.sh /usr/local/bin/tanner-sandbox-entrypoint
RUN chmod 755 /usr/local/bin/tanner-sandbox-entrypoint

ENTRYPOINT ["/usr/local/bin/tanner-sandbox-entrypoint"]
