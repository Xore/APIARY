FROM busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 AS command_rootfs

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS template_rootfs
RUN apk add --no-cache python3 py3-jinja2 py3-mako py3-tornado

FROM docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce

# Seed both emulator images without giving the nested daemon internet access.
COPY --from=command_rootfs / /seed/command-rootfs/
COPY --from=template_rootfs / /seed/template-rootfs/
COPY entrypoint.sh /usr/local/bin/tanner-sandbox-entrypoint
RUN chmod 755 /usr/local/bin/tanner-sandbox-entrypoint

ENTRYPOINT ["/usr/local/bin/tanner-sandbox-entrypoint"]
