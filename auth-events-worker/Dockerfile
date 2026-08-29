FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

LABEL maintainer="honeypot-stack"
LABEL description="Keycloak/gateway authentication-failure telemetry worker (#1066)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.py .

# Fixed, known UID *and* GID (not auto-assigned) so the secrets bind
# mount's ownership can actually be set to match ahead of time -- same
# reasoning as vps/secrets/oidc/*'s "chown root:65532" convention
# (docs/KEYCLOAK-OPERATIONS.md), a different fixed GID here since this is
# an unrelated worker, not oauth2-proxy. `useradd -u 10101` alone auto-picks
# an unrelated GID (999, confirmed live) for the new user's own group --
# groupadd first, then useradd -g, is required to actually get GID 10101.
RUN groupadd -r -g 10101 authevents && useradd -r -u 10101 -g 10101 -s /bin/false authevents
USER authevents

CMD ["python", "-u", "worker.py"]
