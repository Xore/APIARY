FROM busybox:1.38@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616 AS command_rootfs

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS template_rootfs
RUN apk add --no-cache python3 py3-jinja2 py3-mako py3-tornado

FROM docker:29.7.2-dind@sha256:12e683a161823b2a839aeea999b9d960e6e1f9a97b1679ad6b441982e2d9cf07

# Seed both emulator images without giving the nested daemon internet access.
COPY --from=command_rootfs / /seed/command-rootfs/
COPY --from=template_rootfs / /seed/template-rootfs/
COPY entrypoint.sh /usr/local/bin/tanner-sandbox-entrypoint
RUN chmod 755 /usr/local/bin/tanner-sandbox-entrypoint

ENTRYPOINT ["/usr/local/bin/tanner-sandbox-entrypoint"]
