#!/usr/bin/env bash
# test-dashboard-oidc-pkce-totp-login.sh — #982: the OIDC protocol golden-path
# slice that issue's own status comment flagged as the next real step --
# drives one real authorization-code+PKCE login, including the realm's
# mandatory TOTP second factor, against the REAL dashboard binary and a REAL
# disposable Keycloak importing the actual keycloak/realm/apiary-realm.json
# (same import path scripts/test-keycloak-realm-import.sh already proves
# works), not a mock issuer and not a unit test of the verification logic in
# isolation (dashboard/oidc_auth_test.go already covers that, closed #978).
#
# Companion to dashboard/frontend/e2e/{start-dashboard,fake-oidc-issuer}.mjs,
# which deliberately fake the OIDC issuer and pre-seed a session cookie
# instead of driving a real login round trip (see fixture-session.mjs's own
# comment) -- that's correct for what those exist to test (viewport/UI
# layout, #672/#1034), but leaves the actual protocol path unexercised.
# This script is that missing piece.
#
# Keycloak's login and TOTP forms are plain HTML forms -- no browser needed,
# curl drives the whole flow, same pattern as
# scripts/test-oauth2-proxy-gateway-resilience.sh's drive_login().
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
realm_file="${repo_root}/keycloak/realm/apiary-realm.json"

network="dashkc-$$"
pg="dashkc-pg-$$"
kc="dashkc-kc-$$"
redis="dashkc-redis-$$"
kc_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
dash_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
redis_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
fail=0
dash_pid=""

ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }

cleanup() {
  [ -n "${dash_pid}" ] && kill "${dash_pid}" >/dev/null 2>&1 || true
  docker rm -f "${redis}" "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${flow_dir:-}" "${rendered_realm:-}" "${state_dir:-}"
}
trap cleanup EXIT

command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }
command -v go >/dev/null || { printf 'go is required\n' >&2; exit 1; }

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null
for _ in $(seq 1 30); do docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 1; done

# Only the dashboard's own domain needs to become this test's dashboard
# listen address -- Keycloak itself is reached directly by container name,
# never through the realm's own domain substitution. Every OTHER
# *.example.invalid host (kibana, auth, etc.) is left untouched; nothing
# here depends on them resolving to anything.
rendered_realm="$(mktemp)"
sed -E "s|https://honeypot\\.example\\.invalid|http://127.0.0.1:${dash_port}|g" \
  "${realm_file}" > "${rendered_realm}"
chmod 644 "${rendered_realm}"

docker run -d --name "${kc}" --network "${network}" -p "127.0.0.1:${kc_port}:8080" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://127.0.0.1:${kc_port}" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  -v "${rendered_realm}:/opt/keycloak/data/import/apiary-realm.json:ro" \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start --http-port=8080 --import-realm >/dev/null

printf 'Waiting for the disposable Keycloak + realm import (up to 90s)...\n'
for i in $(seq 1 90); do
  docker logs "${kc}" 2>&1 | grep -q "KC-SERVICES0032: Import finished successfully" && break
  if docker logs "${kc}" 2>&1 | grep -q "ERROR: Failed to start server"; then
    printf 'FAIL: realm import crashed the server\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
  [ "$i" -eq 90 ] && { printf 'FAIL: timed out waiting for import\n' >&2; exit 1; }
  sleep 1
done

docker run -d --name "${redis}" --network "${network}" \
  redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2 >/dev/null
for _ in $(seq 1 30); do docker exec "${redis}" redis-cli ping >/dev/null 2>&1 && break; sleep 1; done

kcadm() { docker exec "${kc}" /opt/keycloak/bin/kcadm.sh "$@"; }
kcadm config credentials --server http://localhost:8080 --realm master \
  --user test-admin --password test-only-not-real >/dev/null

client_id=$(kcadm get clients -r apiary -q clientId=apiary-dashboard --fields id --format csv --noquotes | tail -1)
client_secret=$(kcadm get "clients/${client_id}/client-secret" -r apiary --fields value --format csv --noquotes | tail -1)

kcadm create users -r apiary -s username=pkce-totp-test -s enabled=true -s emailVerified=true >/dev/null
kcadm set-password -r apiary --username pkce-totp-test --new-password 'PkceTotpTest9!Extra' >/dev/null
kcadm add-roles -r apiary --uusername pkce-totp-test --rolename apiary-user >/dev/null

# --- #1036: a second, separate user with a Keycloak-admin-set TEMPORARY
# credential -- the real shape of a freshly provisioned account (admin
# hands out a one-time password, user must replace it before doing
# anything else), as opposed to pkce-totp-test above whose password is
# already permanent. -t/--temporary on set-password is what makes Keycloak
# insert its own UPDATE_PASSWORD required action ahead of CONFIGURE_TOTP --
# not something this test sets explicitly.
#
# Found live in CI (2026-08-09): `kcadm update users/<id>/reset-password`
# 404s -- kcadm's generic `update` does a GET-then-PUT against the given
# resource, but reset-password is a write-only action endpoint with no GET,
# so the GET half 404s before the PUT is ever attempted. set-password's own
# -t flag hits the same endpoint correctly (confirmed via
# `kcadm set-password --help` against a real 26.7.1 server) without that
# generic-update assumption.
kcadm create users -r apiary -s username=first-login-test -s enabled=true -s emailVerified=true >/dev/null
kcadm set-password -r apiary --username first-login-test --new-password 'TempOneTime1!Extra' --temporary >/dev/null
kcadm add-roles -r apiary --uusername first-login-test --rolename apiary-user >/dev/null

flow_dir="$(mktemp -d)"
chmod 777 "${flow_dir}"

# --- Complete real TOTP enrollment (CONFIGURE_TOTP is the realm's own
# defaultAction on every fresh user, HmacSHA256 per otpPolicyAlgorithm --
# see keycloak/realm/apiary-realm.json). Raw stdlib TOTP, no pyotp
# dependency, for CI portability. ---
cat > "${flow_dir}/totp.py" <<'PY'
import base64, hashlib, hmac, struct, sys, time
def totp(secret_b32, digest=hashlib.sha256, digits=6, period=30, t=None):
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int((t if t is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, digest).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)
if __name__ == "__main__":
    print(totp(sys.argv[1]))
PY

# Submits a TOTP code, aligned to start early in a fresh 30s window (the
# exact round-trip time from computing a code to Keycloak actually
# verifying it isn't fully bounded -- observed multi-second variance on a
# loaded host -- and landing close enough to a period boundary makes the
# verified-at instant fall on the other side of it even when
# otpPolicyLookAheadWindow: 1 would otherwise tolerate the drift). On a
# genuine rejection, retries with bruteForceProtected's own
# minimumQuickLoginWaitSeconds (60s, +5s margin) cleared first each time,
# so a retry doesn't just fail again for an unrelated reason. Generous
# attempt count deliberately: this is a real, observed source of
# flakiness under host load, not a hypothetical one, and correctness
# matters more than this test's wall-clock time.
#
# $1=cookie jar path, $2=form action URL, $3=the code field's own HTML
# name -- CONFIGURE_TOTP's enrollment form uses "totp", but the login-time
# OTP-challenge form (login-otp.ftl) uses "otp" for the identical-looking
# field; conflating the two under one hardcoded name silently submits an
# empty/wrong field and Keycloak just re-renders the form with no code
# ever actually checked. $4=substring the resulting Location must contain
# to count as real success -- a rejected code sometimes 200-renders the
# same form inline (empty Location, the common case) but sometimes
# redirects back to that same login-actions/authenticate URL instead
# (non-empty Location that still isn't success) -- checking "non-empty"
# alone was caught live falsely treating that second failure shape as a
# win and returning the wrong URL to the caller. Remaining args are extra
# --data-urlencode fields (already flag-prefixed).
#
# Keycloak rotates the form's session_code on every re-render of the same
# execution -- confirmed live: submitting a verified-CORRECT code against
# the action URL captured before an earlier failed attempt still gets
# rejected (stale/consumed session_code), while the identical code against
# a freshly re-scraped action succeeds. This was silently making every
# retry after the first fail regardless of code correctness, since $action
# was captured once by the caller and reused verbatim across all 5
# attempts. Re-scrape it from each rejection's own response body instead.
submit_totp_with_retry() {
  local jar="$1" action="$2" field="$3" success_substr="$4"
  shift 4
  local result="" attempt code into_period hdr_file body_file new_action
  hdr_file="$(mktemp)"
  body_file="$(mktemp)"
  for attempt in 1 2 3 4 5; do
    into_period=$(python3 -c 'import time; print(int(time.time()) % 30)')
    [ "${into_period}" -gt 10 ] && sleep "$((30 - into_period + 1))"
    code=$(python3 "${flow_dir}/totp.py" "${totp_secret}")
    curl -s -c "${jar}" -b "${jar}" -D "${hdr_file}" -o "${body_file}" --data-urlencode "${field}=${code}" "$@" "${action}"
    result=$(grep -i '^location:' "${hdr_file}" | tail -1 | sed 's/^[Ll]ocation: //' | tr -d '\r' || true)
    case "${result}" in
      *"${success_substr}"*) break ;;
    esac
    printf '    (TOTP submit attempt %d rejected, retrying after brute-force cooldown)\n' "${attempt}" >&2
    result=""
    new_action=$(grep -o 'action="[^"]*"' "${body_file}" | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
    [ -n "${new_action}" ] && action="${new_action}"
    sleep 65
  done
  rm -f "${hdr_file}" "${body_file}"
  echo "${result}"
}

# Drives a CONFIGURE_TOTP required-action page (the "Unable to scan?"
# manual-mode link -> secret capture -> submit) to completion. Shared by
# the standalone enrollment flow and the first-login flow below, both of
# which land on this same page shape via different paths. Sets the two
# globals _totp_enroll_secret and _totp_enroll_callback rather than
# echoing a delimited string -- both values are needed by callers and
# either can legitimately be empty on failure.
# $1=cookie jar path, $2=the CONFIGURE_TOTP page body, $3=success substring
complete_totp_enrollment() {
  local jar="$1" totp_page="$2" success_substr="$3"
  local manual_link manual_page form_action secret_field
  manual_link=$(echo "${totp_page}" | grep -o 'href="[^"]*mode=manual[^"]*"' | head -1 | sed 's/^href="//;s/"$//' | sed 's/&amp;/\&/g')
  if [ -z "${manual_link}" ]; then
    printf 'FAIL: no "Unable to scan?" manual-mode link found on the CONFIGURE_TOTP page -- response follows\n' >&2
    echo "${totp_page}" >&2
    exit 1
  fi
  manual_page=$(curl -s -c "${jar}" -b "${jar}" "${manual_link}")
  # Deliberately NOT `local` -- submit_totp_with_retry reads this same
  # name as a global (it computes its TOTP code from whatever
  # ${totp_secret} currently holds, rather than taking it as a parameter,
  # since it was written for the single-enrollment case where that's
  # always the right value). Any caller of this function past the first
  # must account for this global getting overwritten here.
  totp_secret=$(echo "${manual_page}" | grep -oE '[A-Z2-7]{4}( [A-Z2-7]{4}){7}' | head -1 | tr -d ' ')
  if [ -z "${totp_secret}" ]; then
    printf 'FAIL: no TOTP secret found on the manual-mode CONFIGURE_TOTP page -- response follows\n' >&2
    echo "${manual_page}" >&2
    exit 1
  fi
  form_action=$(echo "${manual_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
  secret_field=$(echo "${manual_page}" | grep -o 'id="totpSecret"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
  _totp_enroll_secret="${totp_secret}"
  _totp_enroll_callback=$(submit_totp_with_retry "${jar}" "${form_action}" totp "${success_substr}" --data-urlencode "totpSecret=${secret_field}" --data-urlencode "userLabel=")
}

# Runs directly on the host, not inside a throwaway container: Keycloak's
# KC_HOSTNAME is set to its host-published address (127.0.0.1:${kc_port}),
# so every absolute URL it embeds in its own login/TOTP form actions
# (independent of whatever hostname the *first* request came in on) uses
# that address -- a curl running inside a docker-network container would
# resolve that same "127.0.0.1" to its own container-local loopback
# instead of the actual published Keycloak port, and every request past
# the first would fail to connect. Same reasoning the main golden-path
# flow below already follows.
jar_enroll="${flow_dir}/jar-enroll.txt"
# Keycloak's own authorize endpoint serves the login form directly as a
# 200 OK HTML response when there's no active session -- it does not
# redirect to a separate login page the way oauth2-proxy's /oauth2/start
# does (that pattern belongs to the gateway test, not this direct-to-
# Keycloak one; the two are genuinely different response shapes).
enroll_login_page=$(curl -s -c "${jar_enroll}" -b "${jar_enroll}" "http://127.0.0.1:${kc_port}/realms/apiary/protocol/openid-connect/auth?client_id=apiary-dashboard&redirect_uri=http%3A%2F%2F127.0.0.1%3A${dash_port}%2Fauth%2Fcallback&response_type=code&scope=openid&state=enrollstate&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
enroll_form_action=$(echo "${enroll_login_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
# -L: the password step redirects (302) to the CONFIGURE_TOTP
# required-action page rather than rendering it inline, since TOTP is a
# mandatory default action for every user in this realm.
enroll_totp_page=$(curl -sL -c "${jar_enroll}" -b "${jar_enroll}" --data-urlencode "username=pkce-totp-test" --data-urlencode "password=PkceTotpTest9!Extra" --data-urlencode "credentialId=" "${enroll_form_action}")
# The default (scan-QR-code) view only embeds the secret inside the QR
# code's PNG image, not as text -- the plain-text secret only appears
# after following the page's own "Unable to scan?" (mode=manual) link.
# Keycloak renders it space-grouped for readability (e.g. "JBGH Q4DM
# JRGX ..."), not as one contiguous base32 run. See complete_totp_enrollment().
complete_totp_enrollment "${jar_enroll}" "${enroll_totp_page}" "127.0.0.1:${dash_port}/auth/callback"
totp_secret="${_totp_enroll_secret}"
enroll_callback="${_totp_enroll_callback}"
if [ -z "${enroll_callback}" ]; then
  printf 'FAIL: TOTP enrollment code was rejected across all retry attempts\n' >&2
  exit 1
fi
printf 'TOTP enrolled for pkce-totp-test, secret captured, callback=%s\n' "${enroll_callback}"

# --- Redis first, published on the host and confirmed responsive, BEFORE
# the dashboard binary starts. Redis is only reachable inside the docker
# network by container name -- publish it to the host too so the host-run
# `go run .` process below can reach it. Found live in CI (not locally,
# where `go run .`'s own compile time happened to provide enough of a
# head start): starting the dashboard first and standing Redis up
# afterward is a real race, not just a cosmetic ordering choice -- the
# dashboard's OIDC init connects to Redis synchronously at startup and
# exits outright (doesn't retry) if that first connection attempt fails,
# and a warm Go build cache (e.g. a prior script in the same CI job
# already compiled this exact binary) makes the dashboard reach that
# connection attempt fast enough to lose the race against Redis's own
# container start + readiness poll. ---
docker rm -f "${redis}" >/dev/null 2>&1 || true
docker run -d --name "${redis}" -p "127.0.0.1:${redis_port}:6379" \
  redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2 >/dev/null
for _ in $(seq 1 30); do docker exec "${redis}" redis-cli ping >/dev/null 2>&1 && break; sleep 1; done

# --- Build and start the real dashboard binary against this disposable
# Keycloak + the real Redis just confirmed up. ELASTICSEARCH_URL left
# unset -- optional per main.go (only some features go nil without it),
# not required for the OIDC login path itself. ---
state_dir="$(mktemp -d)"
mkdir -p "${state_dir}/logs/cowrie" "${state_dir}/payloads"
(
  cd "${repo_root}/dashboard"
  LISTEN_ADDR="127.0.0.1:${dash_port}" \
  LOG_DIR="${state_dir}/logs" \
  SCRIPT_PAYLOAD_DIR="${state_dir}/script-payloads" \
  EXPECTED_SENSORS="cowrie" \
  INTELLIGENCE_STATE_FILE="${state_dir}/intelligence.json" \
  DASHBOARD_CONFIG_FILE="${state_dir}/config.json" \
  DASHBOARD_USERS_FILE="${state_dir}/users.json" \
  DASHBOARD_AUDIT_FILE="${state_dir}/audit.jsonl" \
  DASHBOARD_CONFIG_HISTORY_FILE="${state_dir}/config-history.jsonl" \
  DASHBOARD_REPORTS_FILE="${state_dir}/reports.json" \
  PAYLOAD_DIRS="${state_dir}/payloads" \
  OIDC_ISSUER_URL="http://127.0.0.1:${kc_port}/realms/apiary" \
  OIDC_EXTERNAL_URL="http://127.0.0.1:${dash_port}" \
  OIDC_CLIENT_SECRET=${client_secret} \
  OIDC_SESSION_REDIS_URL="redis://127.0.0.1:${redis_port}" \
  go run . > "${state_dir}/dashboard.log" 2>&1 &
  echo $! > "${state_dir}/dash.pid"
)
sleep 1
dash_pid=$(cat "${state_dir}/dash.pid")

dash_up=0
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${dash_port}/healthz" 2>/dev/null || true)
  [ "${code}" = "200" ] && { dash_up=1; break; }
  sleep 1
done
if [ "${dash_up}" -ne 1 ]; then
  printf 'FAIL: dashboard never came up -- log follows\n' >&2
  cat "${state_dir}/dashboard.log" >&2
  exit 1
fi

# --- The real golden path: /auth/login -> real Keycloak PKCE authorize ->
# real password+OTP form submit -> real /auth/callback -> protected page
# reachable. Deliberately NOT the enrollment callback captured above --
# that authorize request was hand-built directly against Keycloak (the
# dashboard binary isn't even running yet at that point in this script),
# with an arbitrary code_challenge/state that the dashboard's own OIDC
# client never generated or bound to a session. Confirmed live: exchanging
# it via the dashboard yields "expired or invalid OIDC state" -- correct,
# expected behavior for a real CSRF-bound OIDC client, not a bug. Only
# this real, dashboard-initiated flow is valid to exchange through
# /auth/callback; enrollment's only job above was creating the TOTP
# credential server-side. ---
jar="${flow_dir}/jar-golden.txt"
auth_location=$(curl -s -c "${jar}" -D - -o /dev/null "http://127.0.0.1:${dash_port}/auth/login" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
case "${auth_location}" in
  "http://127.0.0.1:${kc_port}/realms/apiary/protocol/openid-connect/auth?"*"client_id=apiary-dashboard"*"code_challenge_method=S256"*)
    ok "dashboard /auth/login redirects to the real Keycloak authorize endpoint with PKCE S256" ;;
  *) bad "unexpected /auth/login redirect target: ${auth_location}" ;;
esac

login_page=$(curl -s -c "${jar}" -b "${jar}" "${auth_location}")
form_action=$(echo "${login_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
# -L: the password step redirects (302) to the next execution in the
# flow (the OTP challenge) rather than rendering it inline.
totp_page=$(curl -sL -c "${jar}" -b "${jar}" --data-urlencode "username=pkce-totp-test" --data-urlencode "password=PkceTotpTest9!Extra" --data-urlencode "credentialId=" "${form_action}")
totp_form_action=$(echo "${totp_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
if [ -z "${totp_form_action}" ]; then
  bad "no OTP form found after password submit -- got: $(echo "${totp_page}" | head -c 200)"
else
  # This form also carries a required hidden "selectedCredentialId" field
  # identifying which OTP credential to verify the code against --
  # omitting it doesn't fail gracefully, it just verifies against nothing/
  # the wrong thing and always reports "Invalid authenticator code"
  # regardless of whether the submitted code was actually correct. Same
  # class of easy-to-miss required-hidden-field issue as CONFIGURE_TOTP's
  # own "totpSecret" field during enrollment above. Confirmed via kcadm
  # this scraped value does match the real stored credential ID.
  selected_credential_id=$(echo "${totp_page}" | grep -o 'id="selectedCredentialId"[^>]*value="[^"]*"' | head -1 | grep -o 'value="[^"]*"' | sed 's/value="//;s/"$//')
  callback_url=$(submit_totp_with_retry "${jar}" "${totp_form_action}" otp "127.0.0.1:${dash_port}/auth/callback" --data-urlencode "selectedCredentialId=${selected_credential_id}")
  case "${callback_url}" in
    "http://127.0.0.1:${dash_port}/auth/callback"*)
      ok "real password+TOTP login succeeded, Keycloak issued a real authorization code back to the dashboard" ;;
    *) bad "unexpected redirect after TOTP submit: ${callback_url}" ;;
  esac

  # The dashboard's own /auth/callback handler redirects with 303 See
  # Other (Go's http.Redirect with StatusSeeOther, the correct choice for
  # a post-callback redirect so a page refresh doesn't resubmit) -- not
  # Keycloak's own 302s seen earlier in this flow. Accept either.
  first_status=$(curl -s -o /dev/null -w '%{http_code}' -c "${jar}" -b "${jar}" "${callback_url}")
  protected_status=$(curl -s -o /dev/null -w '%{http_code}' -b "${jar}" "http://127.0.0.1:${dash_port}/")
  if { [ "${first_status}" = "302" ] || [ "${first_status}" = "303" ]; } && [ "${protected_status}" = "200" ]; then
    ok "real PKCE authorization-code exchange succeeded end to end, dashboard session established (protected page 200)"
  else
    bad "callback/protected page did not grant a real session: callback=${first_status} protected=${protected_status}"
  fi

  # --- Authorization codes are single-use -- replaying the exact same
  # callback URL a second time must fail, not silently re-grant a session. ---
  replay_status=$(curl -s -o /dev/null -w '%{http_code}' -c "${flow_dir}/jar-replay.txt" -b "${flow_dir}/jar-replay.txt" "${callback_url}")
  if { [ "${replay_status}" != "302" ] && [ "${replay_status}" != "303" ]; } || [ "$(curl -s -o /dev/null -w '%{http_code}' -b "${flow_dir}/jar-replay.txt" "http://127.0.0.1:${dash_port}/")" != "200" ]; then
    ok "replaying the same authorization code a second time does not grant a session (single-use code enforced)"
  else
    bad "the same authorization code was accepted twice -- code reuse is not being rejected"
  fi
fi

# --- #1036: first-login-test's password was set with temporary=true
# (above) -- Keycloak must force UPDATE_PASSWORD before anything else,
# including before the CONFIGURE_TOTP enrollment this same fresh account
# also owes it. Proves the "admin hands out a one-time password" path
# actually works, not just the "password is already permanent" path
# pkce-totp-test exercises above. Run last, not alongside that enrollment:
# complete_totp_enrollment() overwrites the shared ${totp_secret} global
# that the golden-path login above still depends on for its own OTP
# challenge -- ordering this after that whole flow finishes avoids the
# clash rather than plumbing the secret through as a parameter everywhere
# submit_totp_with_retry is already called. ---
jar_first_login="${flow_dir}/jar-first-login.txt"
first_login_page=$(curl -s -c "${jar_first_login}" -b "${jar_first_login}" "http://127.0.0.1:${kc_port}/realms/apiary/protocol/openid-connect/auth?client_id=apiary-dashboard&redirect_uri=http%3A%2F%2F127.0.0.1%3A${dash_port}%2Fauth%2Fcallback&response_type=code&scope=openid&state=firstloginstate&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
first_login_form_action=$(echo "${first_login_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
# -L: the password step redirects (302) straight to the UPDATE_PASSWORD
# required-action page (Keycloak orders its own pending required actions
# with this one first), not to CONFIGURE_TOTP yet.
update_password_page=$(curl -sL -c "${jar_first_login}" -b "${jar_first_login}" --data-urlencode "username=first-login-test" --data-urlencode "password=TempOneTime1!Extra" --data-urlencode "credentialId=" "${first_login_form_action}")
update_password_form_action=$(echo "${update_password_page}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | sed 's/&amp;/\&/g')
if [ -z "${update_password_form_action}" ] || ! echo "${update_password_page}" | grep -q 'name="password-new"'; then
  bad "temporary-password login did not land on the expected UPDATE_PASSWORD form"
else
  # -L: submitting the new password redirects on to CONFIGURE_TOTP, the
  # account's other pending required action.
  first_login_totp_page=$(curl -sL -c "${jar_first_login}" -b "${jar_first_login}" --data-urlencode "password-new=FirstLoginPerm2!Extra" --data-urlencode "password-confirm=FirstLoginPerm2!Extra" "${update_password_form_action}")
  if ! echo "${first_login_totp_page}" | grep -qi 'mode=manual'; then
    bad "first-login account did not proceed to CONFIGURE_TOTP after its forced password replacement"
  else
    ok "first-login temporary password was rejected as a login credential and forced UPDATE_PASSWORD before granting access"
    complete_totp_enrollment "${jar_first_login}" "${first_login_totp_page}" "127.0.0.1:${dash_port}/auth/callback"
    if [ -z "${_totp_enroll_callback}" ]; then
      bad "first-login account's post-password-reset TOTP enrollment was rejected across all retry attempts"
    else
      ok "first-login account completed forced password replacement + mandatory TOTP enrollment, reached a real authorization code"
    fi
  fi
fi

if [ "${fail}" -ne 0 ]; then
  printf '\nFAIL: one or more dashboard OIDC PKCE+TOTP assertions failed\n' >&2
  exit 1
fi
printf '\nPASS: real PKCE + mandatory-TOTP login against the real dashboard binary and a real disposable Keycloak held\n'
