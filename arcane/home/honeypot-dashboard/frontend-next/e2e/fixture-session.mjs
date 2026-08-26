import { execFile } from "node:child_process";

// The BFF resolves the operator identity from a redis-backed session
// (lib/session.server.ts: key bff:session:<sid>, JSON Session payload,
// cookie __Host-apiary_bff). Rather than drive the real Keycloak flow —
// that is what #1039's disposable-realm suite covers — this seeds
// already-valid sessions directly in exactly the shape getSessionUser()
// reads back, one per role, and dashboard.spec.ts sets the matching cookie
// on each browser context before navigating.
//
// Works even with OIDC_DISABLED=1 in play (the dev fixture fallback): the
// redis lookup runs before that fallback, so a seeded session always wins,
// and contexts without a seeded cookie resolve as the dev admin.

export const SESSION_COOKIE_NAME = "__Host-apiary_bff";

export function fixtureSid(role) {
  return `e2e-fixture-${role}-session`;
}

export async function seedFixtureSessions(redisURL) {
  const base = 1_700_000_000_000;
  for (const role of ["admin", "user"]) {
    await redisSet(
      redisURL,
      `bff:session:${fixtureSid(role)}`,
      JSON.stringify({
        sub: `e2e-${role}`,
        username: `${role}-e2e`,
        displayName: `E2E ${role[0].toUpperCase()}${role.slice(1)}`,
        role,
        createdAt: base,
      }),
    );
  }
}

function redisSet(redisURL, key, value) {
  const parsed = new URL(redisURL);
  return new Promise((resolvePromise, reject) => {
    execFile("redis-cli", ["-h", parsed.hostname, "-p", parsed.port, "SET", key, value, "EX", String(12 * 60 * 60)], (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`redis-cli SET failed: ${stderr || error.message}`));
        return;
      }
      resolvePromise(stdout);
    });
  });
}
