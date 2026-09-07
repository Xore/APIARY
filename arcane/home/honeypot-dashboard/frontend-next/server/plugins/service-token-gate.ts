// #2183 boot gate, nitro-plugin flavor. Registered explicitly in
// vite.config.ts (`nitro({ plugins: [...] })`) so it is evaluated while the
// server bundle boots — before the listener accepts traffic — regardless of
// how the tier is started (cluster.mjs primary/workers or index.mjs
// directly). The decision itself lives in src/lib/serviceToken.server.ts,
// shared verbatim with proxyToRust's per-request backstop; backend-service
// renders the same contract in Rust (main.rs's resolve_service_token).
//
// #3112: assertOidcDisabledPolicy shares this same boot timing requirement
// (backend.server.ts's module scope is only evaluated lazily on first
// import when started via index.mjs directly, which would let a leaked
// OIDC_DISABLED=1 serve one request as a fixture admin before refusing) —
// one plugin, two boot assertions, rather than a second plugin.
import { assertServiceTokenPolicy } from '../../src/lib/serviceToken.server'
import { assertOidcDisabledPolicy } from '../../src/lib/oidc.server'

export default function serviceTokenGate() {
  assertServiceTokenPolicy()
  assertOidcDisabledPolicy()
}
