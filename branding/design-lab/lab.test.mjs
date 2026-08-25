// The design lab's read-only guarantee, asserted against the real harness
// process rather than by reading its source (#1828).
//
// This is the requirement the whole tool exists to satisfy: the lab points a
// dashboard at real captured Elasticsearch data, so "we won't call the write
// paths" is not good enough. A stand-in backend records everything that
// reaches it, and the test fails if a write ever does.
//
//   node --test branding/design-lab/lab.test.mjs
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import assert from 'node:assert/strict'

const LAB = join(dirname(fileURLToPath(import.meta.url)), 'lab.mjs')

// Stand in for the real Rust backend so the test needs no infrastructure --
// and so a write reaching it is observable rather than merely unlikely.
const reachedUpstream = []
const upstream = createServer((req, res) => {
  reachedUpstream.push(`${req.method} ${req.url}`)
  res.writeHead(200, { 'content-type': 'application/json' })
  res.end('{"ok":true}')
})
await new Promise((r) => upstream.listen(19099, '127.0.0.1', r))

// The real harness, not a re-creation of it -- named with a stylesheet that
// does not exist so it starts its servers without spawning vite.
const child = spawn('node', [LAB, 'definitely-not-a-real-variant.css'], {
  env: { ...process.env, APIARY_BACKEND: 'http://127.0.0.1:19099' },
  stdio: ['ignore', 'pipe', 'pipe'],
})
let out = ''
child.stdout.on('data', (d) => (out += d))
child.stderr.on('data', (d) => (out += d))

await new Promise((r) => setTimeout(r, 1500))

// 1. A read is forwarded.
const read = await fetch('http://127.0.0.1:19199/api/v1/source-health')
test('a read is forwarded to the backend', () => {
  assert.equal(read.status, 200)
  assert.deepEqual(reachedUpstream, ['GET /api/v1/source-health'])
})

// 2. A delete is refused *and never reaches upstream* -- the whole point.
const before = reachedUpstream.length
const del = await fetch('http://127.0.0.1:19199/api/v1/stores/events/abc123', { method: 'DELETE' })
test('a delete is refused', () => assert.equal(del.status, 405))
test('the delete never reached the backend', () => assert.equal(reachedUpstream.length, before))

// 3. A preferences PUT, likewise.
const put = await fetch('http://127.0.0.1:19199/api/v1/preferences', { method: 'PUT', body: '{}' })
test('a preferences write is refused', () => assert.equal(put.status, 405))
test('the preferences write never reached the backend', () => assert.equal(reachedUpstream.length, before))

// 4. The write-capable tier is absent, not merely unused.
const mounted = await fetch('http://127.0.0.1:19198/api/v1/sandbox/submit', { method: 'POST' })
const mountedBody = await mounted.json()
test('the write-capable tier is absent, not merely unused', () => {
  assert.equal(mounted.status, 503)
  assert.equal(mountedBody.error, 'write-capable backend absent')
})

// 5. Even a GET to the mounted tier finds nothing -- absence is total.
const mountedGet = await fetch('http://127.0.0.1:19198/api/v1/sandbox/status')
test('the write-capable tier is absent for reads too', () => assert.equal(mountedGet.status, 503))

// 6. The playground is served on its documented port.
const playground = await fetch('http://127.0.0.1:19300/elements.html')
test('the elements playground is on its documented port', () => assert.equal(playground.status, 200))

test.after(() => {
  child.kill('SIGTERM')
  upstream.close()
  if (process.env.LAB_TEST_VERBOSE) console.log(out.trim())
})
