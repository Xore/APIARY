// #2183 boot gate, nitro-plugin flavor. Registered explicitly in
// vite.config.ts (`nitro({ plugins: [...] })`) so it is evaluated while the
// server bundle boots — before the listener accepts traffic — regardless of
// how the tier is started (cluster.mjs primary/workers or index.mjs
// directly). The decision itself lives in src/lib/serviceToken.server.ts,
// shared verbatim with proxyToRust's per-request backstop; backend-service
// renders the same contract in Rust (main.rs's resolve_service_token).
import { assertServiceTokenPolicy } from '../../src/lib/serviceToken.server'

export default function serviceTokenGate() {
  assertServiceTokenPolicy()
}
