#!/usr/bin/env node
// #3315: write the build-stamp file this tier serves at /build.json.
//
// The problem: nothing could say which commit a running dashboard-next was
// built from. `docker images` showed no labels at all for the image, and the
// container's /healthz answers a fixed "ok", so "did the merge that closed
// #3310 actually reach the host?" was answered by comparing image creation
// times against merge times by eye -- the inference docs/ARCANE-GIT-SYNC.md
// calls out as the reason a green, healthy container can be running old code.
//
// A static file rather than a server route, on purpose. Nitro serves the
// build's `public/` directory at the server root, and this image already
// depends on that: the container HEALTHCHECK fetches /static/theme.css, which
// is public/static/theme.css. /build.json rides the same, already-exercised
// path, so it cannot be a route that the file-based generator fails to
// register, fails to give a clean path for (a literal `.` in a TanStack file
// route's name is not something to bet a deploy check on), or shadows behind
// SSR. There is nothing to import and no server code to run.
//
// Usage: write-build-info.mjs [--out <file>]
//   GIT_SHA     the revision, from `docker build --build-arg GIT_SHA=...`.
//               Absent is normal -- a developer building this by hand gets
//               "unknown", never a broken build and never a plausible lie.
//   GIT_SOURCE  repository URL recorded alongside it. Defaults to this repo.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const DEFAULT_OUT = 'public/build.json'
const DEFAULT_SOURCE = 'https://github.com/Xore/APIARY'
export const UNKNOWN_REVISION = 'unknown'

/**
 * A git object name is 7-64 hex characters, optionally `sha256:`-prefixed
 * (git's own object-format naming); anything else is not a revision.
 *
 * Deliberately the same rule as backend-service's `normalize_revision`
 * (src/main.rs) rather than a looser "trim and hope": the two stamps are
 * compared against each other by scripts/verify-deploy.sh, and a value that
 * reads as a revision in one tier and as junk in the other is a disagreement
 * the operator has to debug. Keep the two in step --
 * scripts/tests/test_3315_image_revision.py pins one corpus against both.
 */
export function normalizeRevision(raw) {
  const candidate = (raw ?? '').trim().replace(/^sha256:/, '')
  const isObjectName = candidate.length >= 7 && candidate.length <= 64 &&
    /^[0-9a-fA-F]+$/.test(candidate)
  return isObjectName ? candidate.toLowerCase() : UNKNOWN_REVISION
}

function parseArgs(argv) {
  let out = DEFAULT_OUT
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') {
      const value = argv[i + 1]
      if (!value) {
        console.error('write-build-info: --out needs a value')
        process.exit(2)
      }
      out = value
      i += 1
    } else {
      console.error(`write-build-info: unknown argument: ${argv[i]}`)
      process.exit(2)
    }
  }
  return { out }
}

const { out } = parseArgs(process.argv.slice(2))
const doc = {
  // toISOString() is UTC by definition, which is why it and not a hand-rolled
  // local-time format: scripts/check-timestamp-utc.py polices every Z-suffixed
  // stamp in this repo and a wall-clock one would be wrong twice a year.
  built: new Date().toISOString(),
  revision: normalizeRevision(process.env.GIT_SHA),
  source: (process.env.GIT_SOURCE ?? '').trim() || DEFAULT_SOURCE,
}

const target = resolve(out)
mkdirSync(dirname(target), { recursive: true })
// Key order is the read order: what a human opens /build.json for is `revision`
// first, and alphabetical would bury it under `built`.
writeFileSync(target, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
console.log(`write-build-info: ${target} revision=${doc.revision}`)
