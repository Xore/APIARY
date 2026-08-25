#!/usr/bin/env node
// The design lab's variant harness (#1828).
//
// Reviewing a theme against fixtures tells you the theme looks fine against
// fixtures. Both previous design refreshes were run against real captured
// data and that is what shipped, so #1753 wants the nine themes drafted the
// same way -- which needs a dashboard pointed at the real Elasticsearch that
// structurally cannot write to it.
//
// The Go harness this replaces (dev_serve_test.go, lost with cb77cdf8) got
// that by constructing the server with nil write-services. frontend-next has
// no such handle: it reaches data over HTTP through two bases, and the
// mounted one is write-capable by definition (see backend.server.ts). So the
// same guarantee is made at that seam instead --
//
//   BACKEND_URL          -> a gate that forwards GET/HEAD and refuses the
//                           rest with 405, so a delete is a visible failure
//   BACKEND_MOUNTED_URL  -> nothing at all; every request 503s
//
// -- which is stronger than the original rather than weaker: it is enforced
// per request at runtime, not by remembering to pass nil.
//
// This matters concretely. The Rust tier really does expose stores.rs's
// generic_delete, preferences.rs's put, the honeyfs implant writer and the
// canarytoken minter. A reviewer clicking around a variant would otherwise
// delete real documents and mint real tokens against live infrastructure.
//
// Usage:
//   node branding/design-lab/lab.mjs                       # v5-picks-override.css
//   node branding/design-lab/lab.mjs a.css b.css           # two variants, side by side
//   APIARY_BACKEND=http://10.8.0.2:8081 node .../lab.mjs   # against the homeserver
//
// Variants land on 19201+, the elements playground on 19300 -- the ports the
// lab has always used, so the review log's links keep resolving.

import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, rmSync, symlinkSync } from 'node:fs'
import { dirname, extname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const LAB = dirname(fileURLToPath(import.meta.url))
const FRONTEND = resolve(LAB, '../../arcane/home/honeypot-dashboard/frontend-next')
const PLAYGROUND = join(LAB, 'playground')

// Where variant stylesheets are exposed to the browser. vite serves public/
// at the root, so a symlink here is reachable at /static/lab/<name>.css with
// no rebuild and no vite config change -- and because it is a symlink, saving
// the source file and reloading is enough to see the change. The directory is
// disposable and gitignored; the lab clears it on every start.
const LINK_DIR = join(FRONTEND, 'public/static/lab')

const GATE_PORT = 19199 // read-only door to the real backend
const ABSENT_PORT = 19198 // the write-capable backend, deliberately not here
const FIRST_VARIANT_PORT = 19201
const MAX_VARIANTS = 5 // 19201-19205, the documented range
const PLAYGROUND_PORT = 19300

const REAL_BACKEND = (process.env.APIARY_BACKEND ?? 'http://127.0.0.1:8081').replace(/\/$/, '')
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
}

const children = []

function log(scope, message) {
  process.stdout.write(`[lab:${scope}] ${message}\n`)
}

/**
 * The read-only door. Anything that is not a read is refused here rather
 * than reaching Elasticsearch, and the refusal is printed -- a variant that
 * quietly stopped working because the lab blocked a write is worse than one
 * that says so.
 */
function startGate() {
  const server = createServer(async (req, res) => {
    if (!READ_METHODS.has(req.method ?? '')) {
      log('gate', `REFUSED ${req.method} ${req.url} -- the lab is read-only`)
      res.writeHead(405, { 'content-type': 'application/json', allow: 'GET, HEAD' })
      res.end(
        JSON.stringify({
          error: 'design lab is read-only',
          detail: `${req.method} ${req.url} was not forwarded. Real captured data is not a scratch pad.`,
        }),
      )
      return
    }
    try {
      const upstream = await fetch(`${REAL_BACKEND}${req.url}`, {
        method: req.method,
        headers: { ...req.headers, host: new URL(REAL_BACKEND).host },
      })
      res.writeHead(upstream.status, Object.fromEntries(upstream.headers))
      if (upstream.body) {
        const reader = upstream.body.getReader()
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          res.write(value)
        }
      }
      res.end()
    } catch (error) {
      log('gate', `upstream ${REAL_BACKEND} unreachable: ${error.message}`)
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'backend unreachable', detail: error.message }))
    }
  })
  server.listen(GATE_PORT, '127.0.0.1', () => log('gate', `read-only -> ${REAL_BACKEND} on :${GATE_PORT}`))
  return server
}

/**
 * The write-capable tier, absent. Returning 503 rather than leaving the port
 * closed is deliberate: a connection refused reads as "the lab is broken",
 * a 503 with this body reads as "this is not something the lab has".
 */
function startAbsentBackend() {
  const server = createServer((req, res) => {
    log('absent', `${req.method} ${req.url} -- no write-capable backend in the lab`)
    res.writeHead(503, { 'content-type': 'application/json' })
    res.end(
      JSON.stringify({
        error: 'write-capable backend absent',
        detail: 'The design lab runs without backend-service-mounted by design. Sandbox, Ghidra and analysis submits do not exist here.',
      }),
    )
  })
  server.listen(ABSENT_PORT, '127.0.0.1', () => log('absent', `write tier absent on :${ABSENT_PORT}`))
  return server
}

function startStatic(root, port, scope) {
  const server = createServer((req, res) => {
    const requested = decodeURIComponent((req.url ?? '/').split('?')[0])
    const path = join(root, requested === '/' ? 'index.html' : requested)
    if (!path.startsWith(root) || !existsSync(path)) {
      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('not found')
      return
    }
    res.writeHead(200, { 'content-type': MIME[extname(path)] ?? 'application/octet-stream' })
    createReadStream(path).pipe(res)
  })
  server.listen(port, '127.0.0.1', () => log(scope, `http://127.0.0.1:${port}/`))
  return server
}

function startVariant(cssFile, port) {
  const source = resolve(LAB, cssFile)
  if (!existsSync(source)) {
    log('variant', `no such stylesheet: ${source}`)
    return null
  }
  const linked = join(LINK_DIR, cssFile.replace(/\//g, '_'))
  symlinkSync(source, linked)
  const href = `/static/lab/${cssFile.replace(/\//g, '_')}`

  const child = spawn('npx', ['vite', 'dev', '--port', String(port), '--strictPort'], {
    cwd: FRONTEND,
    stdio: 'inherit',
    env: {
      ...process.env,
      VARIANT_CSS: href,
      // No login round-trip per variant per page -- the reviewer is looking
      // at type and colour, not at Keycloak.
      OIDC_DISABLED: '1',
      SERVE_MODE: 'all',
      BACKEND_URL: `http://127.0.0.1:${GATE_PORT}`,
      BACKEND_MOUNTED_URL: `http://127.0.0.1:${ABSENT_PORT}`,
    },
  })
  children.push(child)
  log('variant', `${cssFile} -> http://127.0.0.1:${port}/  (css at ${href})`)
  return child
}

function main() {
  const requested = process.argv.slice(2)
  const variants = requested.length ? requested : ['v5-picks-override.css']
  if (variants.length > MAX_VARIANTS) {
    log('lab', `at most ${MAX_VARIANTS} variants (ports ${FIRST_VARIANT_PORT}-${FIRST_VARIANT_PORT + MAX_VARIANTS - 1})`)
    process.exit(2)
  }

  rmSync(LINK_DIR, { recursive: true, force: true })
  mkdirSync(LINK_DIR, { recursive: true })

  const servers = [startGate(), startAbsentBackend(), startStatic(PLAYGROUND, PLAYGROUND_PORT, 'playground')]
  variants.forEach((css, index) => startVariant(css, FIRST_VARIANT_PORT + index))

  const shutdown = () => {
    for (const child of children) child.kill('SIGTERM')
    for (const server of servers) server.close()
    rmSync(LINK_DIR, { recursive: true, force: true })
    process.exit(0)
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

// Exported for the harness's own test; main() only runs when invoked directly.
export { READ_METHODS, GATE_PORT, ABSENT_PORT, FIRST_VARIANT_PORT, MAX_VARIANTS, PLAYGROUND_PORT }

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main()
}
