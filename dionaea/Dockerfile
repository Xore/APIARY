FROM dinotools/dionaea:latest

# No USER directive: the base image already runs as root by default
# (confirmed via `docker inspect --format '{{.Config.User}}'`, empty) so
# dionaea can bind its privileged ports (21, 69, 445, ...); this Dockerfile
# must not change that.
COPY tftp_patch.py /tmp/tftp_patch.py
RUN python3 /tmp/tftp_patch.py \
    && rm /tmp/tftp_patch.py
