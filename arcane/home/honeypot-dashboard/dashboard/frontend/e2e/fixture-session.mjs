import { execFile } from "node:child_process";

// #1034: the global OIDC middleware (dashboard/oidc_auth.go's
// (*oidcAuth).middleware) gates every route except /healthz, /auth/login,
// /auth/callback, and /auth/logout -- so once the dashboard actually boots
// (fake-oidc-issuer.mjs, fake-redis.mjs) it 303-redirects every page.goto()
// in dashboard.spec.ts straight to /auth/login instead of rendering. Rather
// than drive a real authorization-code+PKCE round trip against a fixture
// issuer (that's what #982's real disposable-Keycloak suite is for), this
// seeds an already-valid session directly into the fixture Redis in the
// exact shape identityFromRequest() expects (see oidcSession/
// authenticatedIdentity in dashboard/oidc_auth.go and
// dashboard/authorization.go), and dashboard.spec.ts sets the matching
// cookie on every browser context before navigating.

export const FIXTURE_SESSION_COOKIE_NAME = "__Host-apiary_session";
// validSubject() requires 16-128 chars; introspection.mjs's stub treats the
// access token as literally being the subject, so this same string does
// double duty as both.
export const FIXTURE_SUBJECT = "browser-e2e-fixture-session-subject";
export const FIXTURE_SESSION_COOKIE_VALUE = "browser-e2e-fixture-session-cookie";

export async function seedFixtureSession(redisURL) {
  const now = new Date().toISOString();
  const session = {
    identity: {
      subject: FIXTURE_SUBJECT,
      username: "browser-check",
      display_name: "Browser Check",
      role: "admin",
    },
    access_token: FIXTURE_SUBJECT,
    refresh_token: "",
    token_type: "Bearer",
    id_token: "",
    // Far past the 1-minute-remaining refresh threshold in
    // identityFromRequest() so it never tries to hit a real token endpoint
    // this fixture doesn't implement.
    token_expiry: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    created_at: now,
    last_validated: now,
  };
  await redisCLI(redisURL, ["SET", `oidc:session:${FIXTURE_SESSION_COOKIE_VALUE}`, JSON.stringify(session), "EX", "43200"]);
}

function redisCLI(redisURL, args) {
  const parsed = new URL(redisURL);
  return new Promise((resolvePromise, reject) => {
    execFile("redis-cli", ["-h", parsed.hostname, "-p", parsed.port, ...args], (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`redis-cli ${args[0]} failed: ${stderr || error.message}`));
        return;
      }
      resolvePromise(stdout);
    });
  });
}
