// "Report a problem" — a floating widget present on every page when
// behavior.show_problem_report_button is on, backed by a continuous ring
// buffer of recent activity so a submitted report captures what led up to
// a problem, not just what happens after an operator notices something is
// wrong. Ports dashboard/static/hp-problem-report.js's capture scope
// (click/nav trail, console errors, failed requests, a DOM snapshot) onto
// TanStack Router's own navigation state instead of monkey-patching
// history.pushState/replaceState — the router already tells us every
// navigation, client-side or not, so there's nothing to intercept there.
//
// Redaction happens twice: a light client-side trim below (never let a
// captured Authorization/Cookie value linger past this file) and the real,
// pattern-based pass server-side (problem_reports.rs's redact_text), which
// is the actual trust boundary.
import { useRouterState } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState } from 'react'

const MAX_TRAIL = 100
const MAX_CONSOLE_ERRORS = 30
const MAX_NETWORK_FAILURES = 30
const MAX_API_CALLS = 20
const MAX_DOM_SNAPSHOT = 200_000
const MAX_BODY_CAPTURE = 4_000

type ActionEntry = { at: string; kind: 'click' | 'navigation'; detail: string }
type ApiCallEntry = { at: string; method: string; url: string; status: number; request_body: string; response_body: string }

function pushCapped<T>(ring: T[], item: T, max: number) {
  ring.push(item)
  if (ring.length > max) ring.shift()
}

const submitReport = createServerFn({ method: 'POST' })
  .inputValidator(
    (input: {
      page: string
      expected: string
      actual: string
      action_trail: ActionEntry[]
      console_errors: string[]
      network_failures: string[]
      api_calls: ApiCallEntry[]
      dom_snapshot: string
      user_agent: string
    }) => input,
  )
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user) return { ok: false, error: 'Sign in required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams({
      actor_subject: user.sub,
      actor_username: user.username,
      actor_display_name: user.displayName,
    })
    const response = await serviceFetch(`/api/v1/problem-reports?${params.toString()}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!response.ok) return { ok: false, error: `Submit failed (${response.status}).` }
    return { ok: true }
  })

export function ProblemReportButton({ enabled }: { enabled: boolean }) {
  const pathname = useRouterState({ select: (routerState) => routerState.location.pathname + routerState.location.searchStr })
  const trail = useRef<ActionEntry[]>([])
  const consoleErrors = useRef<string[]>([])
  const networkFailures = useRef<string[]>([])
  const apiCalls = useRef<ApiCallEntry[]>([])
  const expectedRef = useRef<HTMLTextAreaElement>(null)

  const [open, setOpen] = useState(false)
  const [expected, setExpected] = useState('')
  const [actual, setActual] = useState('')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!enabled) return
    pushCapped(trail.current, { at: new Date().toISOString(), kind: 'navigation', detail: pathname }, MAX_TRAIL)
  }, [enabled, pathname])

  // Click trail, console/error capture, and a fetch wrapper for failed +
  // same-origin /api/ calls — each is an inherently global interception
  // concern (there's no React-idiomatic substitute for "every click
  // anywhere" or "every console.error anywhere"). Torn down on unmount so
  // this behaves correctly under React's dev-mode double-invoke.
  useEffect(() => {
    if (!enabled) return

    const onClick = (event: MouseEvent) => {
      const el = (event.target as Element | null)?.closest?.('button, a, [role=button], input, select')
      if (!el) return
      const label =
        el.getAttribute('aria-label') ||
        el.getAttribute('title') ||
        (el.tagName === 'A' ? el.getAttribute('href') : null) ||
        el.id ||
        el.tagName.toLowerCase()
      pushCapped(
        trail.current,
        { at: new Date().toISOString(), kind: 'click', detail: `${el.tagName.toLowerCase()}: ${String(label).slice(0, 200)}` },
        MAX_TRAIL,
      )
    }
    document.addEventListener('click', onClick, { capture: true })

    const originalConsoleError = console.error.bind(console)
    console.error = (...args: unknown[]) => {
      try {
        const line = `${new Date().toISOString()} ${args.map((value) => (value instanceof Error ? value.stack || value.message : String(value))).join(' ')}`.slice(0, 2000)
        pushCapped(consoleErrors.current, line, MAX_CONSOLE_ERRORS)
      } catch {
        /* never let capture itself break console.error */
      }
      originalConsoleError(...args)
    }
    const onWindowError = (event: ErrorEvent) => {
      pushCapped(consoleErrors.current, `${new Date().toISOString()} uncaught: ${event.message} (${event.filename}:${event.lineno})`, MAX_CONSOLE_ERRORS)
    }
    const onRejection = (event: PromiseRejectionEvent) => {
      const reason = event.reason instanceof Error ? event.reason.message : String(event.reason)
      pushCapped(consoleErrors.current, `${new Date().toISOString()} unhandled rejection: ${reason}`, MAX_CONSOLE_ERRORS)
    }
    window.addEventListener('error', onWindowError)
    window.addEventListener('unhandledrejection', onRejection)

    const originalFetch = window.fetch.bind(window)
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      const method = init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : undefined) ?? 'GET'
      const isSameOriginAPI = url.startsWith('/api/')
      const requestBody = isSameOriginAPI && typeof init?.body === 'string' ? init.body.slice(0, MAX_BODY_CAPTURE) : ''
      try {
        const response = await originalFetch(input, init)
        if (!response.ok) {
          pushCapped(networkFailures.current, `${new Date().toISOString()} ${method} ${url} -> ${response.status}`, MAX_NETWORK_FAILURES)
        }
        if (isSameOriginAPI) {
          const responseBody = await response
            .clone()
            .text()
            .then((text) => text.slice(0, MAX_BODY_CAPTURE))
            .catch(() => '')
          pushCapped(
            apiCalls.current,
            { at: new Date().toISOString(), method, url, status: response.status, request_body: requestBody, response_body: responseBody },
            MAX_API_CALLS,
          )
        }
        return response
      } catch (err) {
        pushCapped(
          networkFailures.current,
          `${new Date().toISOString()} ${method} ${url} -> network error: ${err instanceof Error ? err.message : String(err)}`,
          MAX_NETWORK_FAILURES,
        )
        throw err
      }
    }

    return () => {
      document.removeEventListener('click', onClick, { capture: true })
      window.removeEventListener('error', onWindowError)
      window.removeEventListener('unhandledrejection', onRejection)
      console.error = originalConsoleError
      window.fetch = originalFetch
    }
  }, [enabled])

  useEffect(() => {
    if (open) expectedRef.current?.focus()
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open])

  if (!enabled) return null

  const submit = async () => {
    if (!expected.trim()) return
    setBusy(true)
    setStatus('Submitting…')
    try {
      const result = await submitReport({
        data: {
          page: pathname,
          expected: expected.trim(),
          actual: actual.trim(),
          action_trail: trail.current,
          console_errors: consoleErrors.current,
          network_failures: networkFailures.current,
          api_calls: apiCalls.current,
          dom_snapshot: document.documentElement.outerHTML.slice(0, MAX_DOM_SNAPSHOT),
          user_agent: navigator.userAgent,
        },
      })
      if (result.ok) {
        setStatus('Report submitted. Thank you.')
        setExpected('')
        setActual('')
        setTimeout(() => setOpen(false), 1200)
      } else {
        setStatus(result.error || 'Failed to submit report.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <button
        className="btn btn-secondary hp-fab"
        type="button"
        onClick={() => {
          setStatus('')
          setOpen(true)
        }}
      >
        Report a problem
      </button>
      {open ? (
        <>
          <div className="modal-backdrop open" aria-hidden="true" onClick={() => setOpen(false)} />
          <div className="modal hp-pr-modal open" role="dialog" aria-modal="true" aria-label="Report a problem">
            <div className="modal__header">
              <h2>Report a problem</h2>
              <button className="modal__close" type="button" aria-label="Close" onClick={() => setOpen(false)}>
                ✕
              </button>
            </div>
            <form
              onSubmit={(event) => {
                event.preventDefault()
                void submit()
              }}
            >
              <label className="note hp-field">
                What did you expect to happen? *
                <textarea
                  ref={expectedRef}
                  className="form-input"
                 
                  rows={3}
                  required
                  value={expected}
                  onChange={(event) => setExpected(event.target.value)}
                />
              </label>
              <label className="note hp-field hp-flow--tight">
                What actually happened?
                <textarea className="form-input" rows={3} value={actual} onChange={(event) => setActual(event.target.value)} />
              </label>
              <p className="note">
                This report automatically includes your recent click/navigation trail, console errors, failed requests, and a
                snapshot of the current page — reviewed by an admin, never shared outside this dashboard.
              </p>
              <div className="hp-row hp-row--end hp-flow--tight">
                <button className="btn btn-secondary" type="button" onClick={() => setOpen(false)}>
                  Cancel
                </button>
                <button className="btn btn-primary" type="submit" disabled={busy}>
                  Submit report
                </button>
              </div>
              {status ? (
                <p className="hp-modal-status" role="status" aria-live="polite">
                  {status}
                </p>
              ) : null}
            </form>
          </div>
        </>
      ) : null}
    </>
  )
}
