FROM dinotools/dionaea:latest@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca

# No USER directive: the base image already runs as root by default
# (confirmed via `docker inspect --format '{{.Config.User}}'`, empty) so
# dionaea can bind its privileged ports (21, 69, 445, ...); this Dockerfile
# must not change that.
COPY tftp_patch.py /tmp/tftp_patch.py
COPY printer_patch.py /tmp/printer_patch.py
COPY ftp_patch.py /tmp/ftp_patch.py
COPY smb_exploit_patch.py /tmp/smb_exploit_patch.py
COPY sip_patch.py /tmp/sip_patch.py
COPY log_rotation_patch.py /tmp/log_rotation_patch.py
RUN python3 /tmp/tftp_patch.py \
    && python3 /tmp/printer_patch.py \
    && python3 /tmp/ftp_patch.py \
    && python3 /tmp/smb_exploit_patch.py \
    && python3 /tmp/sip_patch.py \
    && python3 /tmp/log_rotation_patch.py \
    && rm /tmp/tftp_patch.py /tmp/printer_patch.py /tmp/ftp_patch.py /tmp/smb_exploit_patch.py /tmp/sip_patch.py /tmp/log_rotation_patch.py
