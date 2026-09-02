// #2826: dashboard-bff's durable JSONL sink (DASHBOARD_BFF_LOG_FILE) mirrored
// obs.rs's line shape but not its size cap -- unbounded by construction.
// This exercises the ported rotate_if_oversized shape directly against a
// real file on disk, the same property backend-service/src/obs.rs's own
// rotation tests assert.
import {
  mkdtempSync, readFileSync, existsSync, rmSync, statSync, truncateSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  flushNamedEventSink, recordNamedEvent, rotateIfOversized, rotatedPath,
} from './obs.server'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'apiary-obs-bff-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('rotateIfOversized', () => {
  it('leaves a file at or under the cap untouched', async () => {
    const file = join(dir, 'app.jsonl')
    writeFileSync(file, 'x'.repeat(10))
    await rotateIfOversized(file, 10)
    expect(existsSync(rotatedPath(file))).toBe(false)
    expect(readFileSync(file, 'utf8')).toBe('x'.repeat(10))
  })

  it('renames the live file aside once it exceeds the cap, dropping any prior generation', async () => {
    const file = join(dir, 'app.jsonl')
    writeFileSync(rotatedPath(file), 'stale-generation')
    writeFileSync(file, 'y'.repeat(11))
    await rotateIfOversized(file, 10)
    expect(existsSync(file)).toBe(false) // caller re-creates it on the next append
    expect(readFileSync(rotatedPath(file), 'utf8')).toBe('y'.repeat(11))
  })

  it('is a no-op when the file does not exist yet', async () => {
    const file = join(dir, 'missing.jsonl')
    await expect(rotateIfOversized(file, 10)).resolves.toBeUndefined()
    expect(existsSync(rotatedPath(file))).toBe(false)
  })
})

describe('named-event sink writes', () => {
  // #2826 review: obs.rs guards rotate->open->write with a tokio Mutex and
  // documents that mutex as measured-necessary ("lets tokio's lazy file
  // lifecycle interleave or defer them across tasks"). The first cut of this
  // port dropped it, and recordNamedEvent fires the write off without
  // awaiting -- so two named events crossing the 25 MiB cap concurrently can
  // both rotate, and the second one's unlink deletes the generation the first
  // just renamed aside. The sink stays bounded either way; what breaks is
  // retention, in the issue whose whole subject is retention.
  //
  // This pins the OUTCOME the single-slot promise chain guarantees -- one
  // retired generation holding the pre-rotation bytes, both lines in the live
  // file in order. It cannot force the losing schedule: that would need the
  // fs calls intercepted, and in this harness vi.mock('node:fs/promises')
  // rewrites only the test file's own imports, never a sibling module's
  // (verified, not assumed). The ordering itself is structural.
  const previous = process.env.DASHBOARD_BFF_LOG_FILE

  afterEach(() => {
    if (previous === undefined) delete process.env.DASHBOARD_BFF_LOG_FILE
    else process.env.DASHBOARD_BFF_LOG_FILE = previous
  })

  it('keeps one retired generation when two events cross the cap at once', async () => {
    const file = join(dir, 'app.jsonl')
    // Sparse, so the 25 MiB cap is crossed without writing 25 MiB.
    writeFileSync(file, '')
    truncateSync(file, 25 * 1024 * 1024 + 1)
    process.env.DASHBOARD_BFF_LOG_FILE = file

    recordNamedEvent('auth_login_started')
    recordNamedEvent('auth_login_completed')
    await flushNamedEventSink()

    expect(statSync(rotatedPath(file)).size).toBe(25 * 1024 * 1024 + 1)
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n')
    expect(lines).toHaveLength(2)
    expect(JSON.parse(lines[0])['event.action']).toBe('auth_login_started')
    expect(JSON.parse(lines[1])['event.action']).toBe('auth_login_completed')
  })

  it('does nothing when no sink file is configured', async () => {
    delete process.env.DASHBOARD_BFF_LOG_FILE
    recordNamedEvent('auth_login_failed')
    await expect(flushNamedEventSink()).resolves.toBeUndefined()
  })
})
