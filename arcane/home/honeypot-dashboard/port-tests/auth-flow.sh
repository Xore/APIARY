#!/bin/bash
# Auth-guard smoke: without OIDC_DISABLED, unauthenticated SSR redirects
# to /auth/login and the API proxies 401. (The full OIDC round trip needs
# Keycloak; this covers the guard wiring.)
source "$(dirname "$0")/lib.sh"
require_es
start_backend
SKIP_FE_BUILD="${SKIP_FE_BUILD:-1}" start_frontend OIDC_DISABLED=0

check "unauthenticated / redirects to login" bash -c \
  "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' $FE_URL/ | grep -Eq '30[27].*/auth/login'"
check_http "unauthenticated chart proxy 401" 401 "$FE_URL/api/chart/os-distribution"
check_http "unauthenticated sse proxy 401" 401 "$FE_URL/api/live"
check_http "blackhole export still open (tunnel trust)" 200 "$FE_URL/export/portbridge-manual-blackhole.txt"

summary
