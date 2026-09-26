// #3330: the alert webhook's delivery outcomes, and the two surfaces that
// exist so a dead webhook is no longer invisible.
//
// Three kinds of assertion, matching what this tier can actually check:
// the pure formatting/tone logic (which is where a wrong answer would
// quietly mislead an operator), the wiring between the two surfaces and
// the endpoint, and the e2e fixture that keeps the card from being covered
// by the catch-all.
//
// The payload rule is the one worth having a test for at all: an alert
// body quotes attacker-controlled text by construction, so if a payload
// field ever reaches the document or the response, this document becomes
// something no operator should be shown.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  describeWebhookAttempt,
  webhookDeliveryNote,
  webhookDeliveryTone,
  type WebhookAttempt,
  type WebhookDelivery,
} from '../lib/webhookDelivery'

// frontend-next/ — two up from src/lib/, so the assertions can reach the
// e2e fixture as well as the route sources.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const read = (path: string) => readFileSync(join(ROOT, path), 'utf8')

const HEALTHY: WebhookDelivery = {
  available: true,
  reason: '',
  state: 'healthy',
  target: 'https://hooks.example.com:443',
  messages: 12,
  consecutive_failures: 0,
  failure_threshold: 5,
  last_success: { at: '2026-09-26T11:40:00Z', status: 'delivered', http_code: 200, latency_ms: 142, tries: 1, error: null },
  last_failure: null,
  updated_at: '2026-09-26T11:40:00Z',
}

const FAILING: WebhookDelivery = {
  ...HEALTHY,
  state: 'failing',
  messages: 137,
  consecutive_failures: 5,
  last_failure: {
    at: '2026-09-26T11:40:00Z',
    status: 'failed',
    http_code: 503,
    latency_ms: 15021,
    tries: 3,
    error: 'HTTP 503 Service Unavailable',
  },
}

describe('webhook delivery tone', () => {
  it('separates healthy, a short streak, and a streak past the threshold', () => {
    // Three distinct signals, not two: a single failed delivery while the
    // last success is still an hour old is not the same fact as five in a
    // row, and collapsing them is how a warning gets ignored.
    expect(webhookDeliveryTone('healthy')).toBe('ok')
    expect(webhookDeliveryTone('degraded')).toBe('warn')
    expect(webhookDeliveryTone('failing')).toBe('bad')
  })

  it('does not paint an unconfigured or unreadable webhook as broken', () => {
    // A deployment with no webhook is the common case and a red badge for
    // it would be crying wolf; an unreadable record is a fault in this
    // tier, not in the operator's webhook, and reads its own copy.
    expect(webhookDeliveryTone('disabled')).toBe('flat')
    expect(webhookDeliveryTone('unknown')).toBe('flat')
    expect(webhookDeliveryTone(undefined)).toBe('flat')
  })
})

describe('webhook delivery note', () => {
  it('names both readings of an absent record', () => {
    // "No delivery recorded" is genuinely ambiguous — unconfigured, or
    // configured and quiet — and those need different actions. The copy
    // says so instead of picking one and sending someone to debug the
    // wrong thing.
    const note = webhookDeliveryNote({ ...HEALTHY, state: 'disabled', last_success: null })
    expect(note).toContain('ALERT_WEBHOOK_URL')
    expect(note).toMatch(/unset|set/)
  })

  it('reports the streak against the threshold the backend published', () => {
    // The number in the prose is read off the response, not hardcoded, so
    // a change to the backend's threshold cannot leave the copy lying.
    const note = webhookDeliveryNote(FAILING)
    expect(note).toContain('5 consecutive failures')
    expect(note).toContain('threshold')
    expect(webhookDeliveryNote({ ...FAILING, consecutive_failures: 1, state: 'degraded' })).toContain('1 consecutive failure,')
  })

  it('distinguishes a failed read from a record with no deliveries', () => {
    // The whole reason for the `available` flag: rendering "nothing has
    // been delivered" after Elasticsearch refused to answer is a lie, and
    // it is a lie in the direction this change exists to stop.
    const unreadable = webhookDeliveryNote({ ...HEALTHY, available: false, reason: 'index_not_found_exception' })
    expect(unreadable).toContain('index_not_found_exception')
    expect(unreadable).not.toContain('No delivery has been recorded')
    expect(webhookDeliveryNote(null)).toContain('could not be read')
  })
})

describe('webhook attempt description', () => {
  it('reads a success and a failure the same shape', () => {
    expect(describeWebhookAttempt(HEALTHY.last_success)).toBe('HTTP 200 · 142ms')
  })

  it('spells out retries, because a triple-tried failure is not a single one', () => {
    expect(describeWebhookAttempt(FAILING.last_failure)).toBe('HTTP 503 · 15.0s · 3 tries')
  })

  it('says "no response" rather than inventing a status for a timeout', () => {
    // There was no status code to read. Printing HTTP 0, or leaving the
    // cell blank, both send an operator to check the wrong layer.
    const timeout: WebhookAttempt = { ...FAILING.last_failure!, http_code: null, latency_ms: 5000, error: 'operation timed out' }
    expect(describeWebhookAttempt(timeout)).toBe('no response · 5.0s · 3 tries')
  })

  it('an absent attempt is an em dash, not an error string', () => {
    expect(describeWebhookAttempt(null)).toBe('—')
    expect(describeWebhookAttempt(undefined)).toBe('—')
  })
})

describe('the two surfaces are both wired to the record', () => {
  it('the diagnostics page renders the card off the same source-health snapshot', () => {
    const page = read('src/routes/source-health.tsx')
    // Off the existing snapshot, not a second request: that page is
    // refreshed on one cycle and one loader, and a second call would
    // make the two surfaces disagree whenever they raced.
    expect(page).toContain('webhook: WebhookDelivery')
    expect(page).toContain('webhookDeliveryNote(webhook)')
    expect(page).toContain('describeWebhookAttempt(webhook.last_failure)')
    expect(page).not.toMatch(/serviceJSON[^)]*webhook-delivery/)
  })

  it('the header chip carries a verdict, and "disabled" is not one', () => {
    // A deployment with no webhook is the common case and is not broken.
    // A badge in the header strip would put a permanent neutral chip in
    // front of every install to say nothing; the card still says it.
    const page = read('src/routes/source-health.tsx')
    expect(page).toMatch(/if \(!delivery \|\| delivery\.state === 'disabled'\) return null/)
    expect(page).toContain('{webhookBadge(webhook)}')
  })

  it('Settings fetches the standalone endpoint and shares one type with the page', () => {
    const settings = read('src/routes/settings.tsx')
    expect(settings).toContain("serviceJSON<WebhookDelivery>('/api/v1/webhook-delivery')")
    expect(settings).toContain('webhookDelivery: fetchWebhookDelivery()')
    // One definition of the shape, imported by both — a second inline copy
    // is a second thing that can quietly stop matching the backend.
    expect(settings).toMatch(/import \{[^}]*\bWebhookDelivery\b[^}]*\} from '\.\.\/lib\/webhookDelivery'/s)
    expect(read('src/routes/source-health.tsx')).toMatch(/from '\.\.\/lib\/webhookDelivery'/)
  })

  it('the card is reachable: registered in the pane rail, search index, and pane', () => {
    const settings = read('src/routes/settings.tsx')
    // useFieldHidden reads SEARCH_INDEX[pane][field]; a card absent from it
    // can never be surfaced by the cross-pane settings search.
    expect(settings).toContain("'webhook-delivery':\n      'honeypot alert webhook delivery")
    expect(settings).toContain('<WebhookDeliveryCard data={webhookDeliveryData} failed={webhookDeliveryFailed} />')
  })

  it('both cards separate an unreadable record from an empty one', () => {
    // Three states, not two. `null` from fetchSettingsData is a failed
    // read, and a card that leaves its skeleton up forever has turned a
    // read error into an absence -- #2311's argument, which this file
    // already applies to the admin panes and this card now follows.
    const settings = read('src/routes/settings.tsx')
    expect(settings).toMatch(/if \(!result\) setWebhookDeliveryFailed\(true\)/)
    expect(settings).toMatch(/failed[\s\S]{0,400}data === null[\s\S]{0,120}skeleton-line/)
    // And the record's own `available: false` is a fourth, separate thing:
    // the read worked, and what it read says the record is not available.
    expect(settings).toMatch(/!data\.available[\s\S]{0,200}webhookDeliveryNote/)

    // The diagnostics page carries one snapshot with its own settled-null
    // flag, so its webhook card names the two failure modes itself: a
    // backend that does not send the field at all, and a field whose
    // record could not be read. Neither may render as a webhook with no
    // deliveries.
    const page = read('src/routes/source-health.tsx')
    expect(page).toMatch(/!webhook[\s\S]{0,200}not part of this backend/)
    expect(page).toMatch(/!webhook\.available[\s\S]{0,200}webhookDeliveryNote/)
  })
})

describe('the record never carries the alert body', () => {
  it('the shared type has no field an attacker-controlled string could ride in on', () => {
    // The fields the backend publishes, exactly. A new one has to be
    // added here deliberately, which is the point.
    const type = read('src/lib/webhookDelivery.ts')
    const attempt = type.slice(type.indexOf('export type WebhookAttempt'), type.indexOf('export type WebhookDelivery'))
    const fields = [...attempt.matchAll(/^\s{2}(\w+)\??:/gm)].map((m) => m[1])
    expect(fields).toEqual(['at', 'status', 'http_code', 'latency_ms', 'tries', 'error'])
    for (const leak of ['content', 'text', 'message', 'body', 'payload']) {
      expect(fields, `"${leak}" must never be a recorded field`).not.toContain(leak)
    }
  })

  it('the e2e fixture cannot quietly grow a payload field either', () => {
    // fake-backend.mjs is hand-written, so the same rule needs the same
    // net here: the fixture mirrors the backend, and a payload field in it
    // would render a card shape the real backend never sends.
    const fixture = read('e2e/fake-backend.mjs')
    const seeded = fixture.slice(fixture.indexOf('function webhookDelivery()'))
    const body = seeded.slice(0, seeded.indexOf('\n}'))
    for (const leak of ['content:', 'text:', 'body:', 'payload:']) {
      expect(body, `"${leak}" in the seeded delivery record`).not.toContain(leak)
    }
  })
})

describe('the e2e fixture keeps the card off the catch-all', () => {
  it('serves both the standalone route and the source-health field', () => {
    // #2507: an unrecognized /api/v1 path used to answer {} invisibly, so
    // a new card silently inherited fallback coverage and its smoke test
    // verified nothing.
    const fixture = read('e2e/fake-backend.mjs')
    expect(fixture).toContain('if (pathname === "/api/v1/webhook-delivery") return webhookDelivery()')
    expect(fixture).toContain('webhook: webhookDelivery()')
  })

  it('seeds the failing state, because that is the one this surface is for', () => {
    const fixture = read('e2e/fake-backend.mjs')
    const seeded = fixture.slice(fixture.indexOf('function webhookDelivery()'), fixture.indexOf('/** Minimal handler table'))
    expect(seeded).toContain('state: "failing"')
    // Origin only, no path -- the backend never records a bot URL's path.
    expect(seeded).toContain('https://hooks.example.com:443')
    expect(seeded).not.toContain('/services/')
  })
})
