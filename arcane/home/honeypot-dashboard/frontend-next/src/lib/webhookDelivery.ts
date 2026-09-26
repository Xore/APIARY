// The alert fan-out's delivery outcomes (#3330), as the Rust tier's
// `webhook_delivery::DeliveryHealth` serializes it.
//
// Two surfaces read this and they must not drift: the Source & pipeline
// health page (off the `webhook` field of /api/v1/source-health, so it
// costs no second round trip) and the Settings operations pane (off
// /api/v1/webhook-delivery). It exists as a named type rather than being
// inlined in each route because the whole point of the change is that a
// dead webhook stops being invisible — a type duplicated across the two
// surfaces is one more thing that can quietly stop matching the backend.
//
// `available: false` means the *record* could not be read, not that there
// were no deliveries. It is the same envelope reporter_stats.rs uses, and
// the two must stay distinguishable: rendering "never delivered" for a
// failed read would be a lie in the exact direction this module exists to
// stop lying.

export type WebhookAttempt = {
  at: string
  status: 'delivered' | 'failed'
  http_code: number | null
  latency_ms: number
  tries: number
  error: string | null
}

export type WebhookDelivery = {
  available: boolean
  reason: string
  /** disabled / idle / healthy / degraded / failing / unknown */
  state: 'disabled' | 'healthy' | 'degraded' | 'failing' | 'unknown'
  /**
   * The webhook URL's origin only — the backend never records the path or
   * query, because that is where a bot's secret token lives. So there is
   * nothing for this tier to redact and nothing an operator can read off
   * it.
   */
  target: string
  messages: number
  consecutive_failures: number
  failure_threshold: number
  last_success: WebhookAttempt | null
  last_failure: WebhookAttempt | null
  updated_at: string
}

/**
 * How a state reads in a badge. The tier behind it is the existing
 * `badge--success` / `badge--warning` / `badge--danger` vocabulary the
 * source-health page already uses for cluster and sensor states, so the
 * webhook verdict sits in the same visual language as everything else on
 * that page rather than introducing a fourth.
 *
 * - healthy   green   — the last delivery landed
 * - degraded  amber   — at least one failed delivery, under the threshold
 * - failing   red     — the streak has reached the threshold; the page warns
 * - disabled  neutral — no delivery has ever been recorded
 * - unknown   neutral — the record could not be read; say so, do not guess
 */
export function webhookDeliveryTone(state: WebhookDelivery['state'] | undefined): 'ok' | 'warn' | 'bad' | 'flat' {
  if (state === 'healthy') return 'ok'
  if (state === 'degraded') return 'warn'
  if (state === 'failing') return 'bad'
  return 'flat'
}

/**
 * The one-line explanation each state earns. `disabled` is the awkward
 * one: an absent record means either ALERT_WEBHOOK_URL is unset on the
 * worker or nothing has notified since, and those need different actions,
 * so the copy names both rather than picking one.
 */
export function webhookDeliveryNote(delivery: WebhookDelivery | null | undefined): string {
  if (delivery === null || delivery === undefined) {
    return 'The delivery record could not be read from Elasticsearch.'
  }
  if (!delivery.available) {
    return `The delivery record could not be read: ${delivery.reason || 'no reason given'}`
  }
  switch (delivery.state) {
    case 'disabled':
      return 'No delivery has been recorded. Either ALERT_WEBHOOK_URL is unset on the worker, or it is set and nothing has notified since.'
    case 'healthy':
      return 'The last delivery was accepted by the webhook.'
    case 'degraded':
      return `${delivery.consecutive_failures} consecutive failure${delivery.consecutive_failures === 1 ? '' : 's'}, under the ${delivery.failure_threshold}-delivery warning threshold. The last accepted delivery is still shown below.`
    case 'failing':
      return `${delivery.consecutive_failures} consecutive failures — at or past the ${delivery.failure_threshold}-delivery warning threshold. Alerts raised in this window are not reaching the webhook.`
    default:
      return 'The delivery state could not be determined.'
  }
}

/** `HTTP 503 · 1.2s · 3 tries`, or an em dash when there is no attempt. */
export function describeWebhookAttempt(attempt: WebhookAttempt | null | undefined): string {
  if (!attempt) return '—'
  const status = attempt.http_code === null ? 'no response' : `HTTP ${attempt.http_code}`
  const latency = attempt.latency_ms >= 1000 ? `${(attempt.latency_ms / 1000).toFixed(1)}s` : `${attempt.latency_ms}ms`
  const tries = attempt.tries > 1 ? ` · ${attempt.tries} tries` : ''
  return `${status} · ${latency}${tries}`
}
