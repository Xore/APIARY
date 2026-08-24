# github.com/gbrindisi/wordpot -- #1421: WordPress/CMS decoy, vendored
# rather than reimplemented (the plugin/theme/login probe route set is
# real detection logic not worth rebuilding). ISC licensed -- permissive,
# no copyleft concern, confirmed directly against the vendored README's
# License section (no separate LICENSE file upstream).
#
# Pinned the same way beelzebub/Dockerfile pins BEELZEBUB_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. WORDPOT_REF is upstream's actual latest commit (confirmed via
# `git log -1` -- the project has had no real commit since 2018, notably
# stale but the only credible option found for this slot, see #1421).
#
# Python 2 only (confirmed directly -- `except Exception, e:`/`iteritems()`
# /print-statement syntax throughout, upstream never ported to 3). Kept
# as-is rather than ported: porting is new work this stack's own
# "vendor, extend when needed" rule doesn't call for, and the container is
# no more privileged or network-reachable than any other sensor here
# (cap_drop, non-root, isolated network -- see docker-compose.wordpot.yml).
#
# wordpot_patch.py closes two real gaps -- see that file's own doc comment
# for both: JSON logging (the literal ask in #1421) and a port-preserving
# REMOTE_ADDR (without it, ip-enrichment-worker's via_port join has
# nothing to join on -- every event's real attacker IP would silently
# stay unresolved forever, the same class of gap hellpot/router_patch.py
# closed for hellpot).
#
# The hpfeeds package (upstream's optional pip dependency, an editable
# git+https install) is never installed here: __init__.py only imports it
# when HPFEEDS_ENABLED is true, and this stack's own wordpot.conf keeps
# that false (see wordpot.conf's own doc comment) -- installing an unused
# third-party git dependency for functionality this stack will never
# enable isn't justified.
FROM python:2.7-alpine
RUN apk add --no-cache git python3 ca-certificates
WORKDIR /opt/wordpot
ARG WORDPOT_REF=e96889bd5a35bbdd9fb2dd4cd583475cf7d25962
RUN git clone https://github.com/gbrindisi/wordpot /opt/wordpot \
 && git checkout "$WORDPOT_REF"
RUN sed -i '/hpfeeds/d' requirements.txt \
 && pip install --no-cache-dir -r requirements.txt
COPY wordpot_patch.py /tmp/wordpot_patch.py
RUN python3 /tmp/wordpot_patch.py
COPY wordpot.conf /opt/wordpot/wordpot.conf

RUN chown -R 65534:65534 /opt/wordpot

EXPOSE 80
# #1908: the Traefik-only listener wordpot_patch.py adds. Not a second
# honeypot -- the same app, so that which door a request arrived at is a
# fact in the log line instead of a guess.
EXPOSE 8090

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 80 || exit 1

ENTRYPOINT ["python", "wordpot.py"]
