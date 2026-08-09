import { createServer } from "node:http";

// #1034: dashboard/oidc_auth.go's newOIDCAuth() does live OIDC discovery
// against OIDC_ISSUER_URL at process startup and refuses to boot if it
// fails, so the e2e dashboard needs *some* issuer to discover against -- a
// real Keycloak is too heavy for this fixture (that's what #982's
// disposable-Keycloak integration suite is for), so this serves just enough
// of the discovery document for oidc.NewProvider to succeed and for the
// explicit introspection_endpoint/end_session_endpoint check right after it
// to pass. It does not implement the authorization/token/introspection
// endpoints for real -- this fixture only needs to get the process past
// startup, not drive a full login.
export function startFakeOIDCIssuer() {
  let base = "";
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://fake-oidc");
    res.setHeader("Content-Type", "application/json");

    if (url.pathname === "/.well-known/openid-configuration") {
      res.writeHead(200);
      res.end(JSON.stringify({
        issuer: base,
        authorization_endpoint: `${base}/protocol/openid-connect/auth`,
        token_endpoint: `${base}/protocol/openid-connect/token`,
        userinfo_endpoint: `${base}/protocol/openid-connect/userinfo`,
        jwks_uri: `${base}/protocol/openid-connect/certs`,
        end_session_endpoint: `${base}/protocol/openid-connect/logout`,
        introspection_endpoint: `${base}/protocol/openid-connect/token/introspect`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      }));
      return;
    }

    if (url.pathname === "/protocol/openid-connect/certs") {
      // Empty JWKS: fine for startup discovery, which never fetches keys.
      // A real login attempt against this fixture would fail signature
      // verification here -- this issuer only exists to get main.go past
      // newOIDCAuth(), not to complete an actual OIDC round trip.
      res.writeHead(200);
      res.end(JSON.stringify({ keys: [] }));
      return;
    }

    if (url.pathname === "/protocol/openid-connect/token/introspect" && req.method === "POST") {
      // dashboard/oidc_auth.go's identityFromRequest() re-introspects every
      // 30s for any session that's still in use, even one seeded directly
      // into Redis by seed-fixture-session.mjs rather than minted through a
      // real login. Fixture access tokens ARE the fixture subject string
      // (see seed-fixture-session.mjs), so echoing it straight back as
      // `sub` is enough to keep introspection.go's subject-match check
      // happy without a real token store.
      readBody(req).then((body) => {
        const token = new URLSearchParams(body).get("token") || "";
        res.writeHead(200);
        res.end(JSON.stringify({ active: Boolean(token), sub: token, client_id: "apiary-dashboard" }));
      });
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: "not stubbed in fake-oidc-issuer" }));
  });

  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      base = `http://127.0.0.1:${port}`;
      resolvePromise({ url: base, close: () => server.close() });
    });
  });
}

function readBody(req) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
