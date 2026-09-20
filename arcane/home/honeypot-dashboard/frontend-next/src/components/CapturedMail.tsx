// The captured SMTP message for one mailoney session (#1611 workstream B),
// shared between the session page and the sensor detail page (#1856).
//
// It lived inside routes/sessions.$id.tsx, which meant the mail sensor's
// own detail view — the page whose entire job is showing what a sensor
// captured — showed an envelope and a truncated preview and never the
// message. A mail sensor that reports "an SMTP session happened" and not
// the mail is not reporting the interesting half.
//
// Plain text only, deliberately: an HTML body is decoded to a string by
// the backend but never rendered, and attachments are listed as metadata
// (name, type, size, sha256) without their bytes — the posture mail.rs's
// own doc comment insists on, so this can be neither an attacker-
// controlled script sink nor a malware distribution point.
import { Skeleton } from './ui/skeleton'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { ErrorStateBlock } from './ErrorState'
import { Button } from './ui/button'
import { Card, CardContent } from './ui/card'
import { Label } from './ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'

export type MailAddress = { name: string; address: string }
export type MailAttachment = { filename: string; content_type: string; size_bytes: number; sha256: string }
export type Mail = {
  session_id: string
  body_path: string
  size_bytes: number
  imported_at: string
  from: MailAddress | null
  to: MailAddress[]
  subject: string
  date: string
  message_id: string
  body_text: string
  attachments: MailAttachment[]
}

export const fetchMail = createServerFn({ method: 'GET' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<Mail | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Mail>(`/api/v1/mail/${encodeURIComponent(data.id)}`)
  })

export function formatAddress(address: MailAddress): string {
  if (!address.address) return address.name || '—'
  return address.name ? `${address.name} <${address.address}>` : address.address
}

/** The message itself: headers, body, attachment metadata. */
export function MailMessage({ mail }: { mail: Mail }) {
  return (
    <>
      <Table className="data-table hp-flow">
        <TableBody>
          <TableRow>
            <TableCell>From</TableCell>
            <TableCell className="v">{mail.from ? formatAddress(mail.from) : '—'}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>To</TableCell>
            <TableCell className="v">{mail.to.length ? mail.to.map(formatAddress).join(', ') : '—'}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Subject</TableCell>
            <TableCell className="v">{mail.subject || '—'}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Date</TableCell>
            <TableCell>{mail.date || '—'}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Message-ID</TableCell>
            <TableCell className="v">{mail.message_id || '—'}</TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Size</TableCell>
            <TableCell className="n">{mail.size_bytes.toLocaleString('en-US')} bytes</TableCell>
          </TableRow>
        </TableBody>
      </Table>
      <Label>Body</Label>
      <pre className="code">{mail.body_text || '(empty body)'}</pre>
      {mail.attachments.length > 0 ? (
        <>
          <Label>Attachments</Label>
          <Table className="data-table">
            <TableHeader>
              <TableRow>
                <TableHead>filename</TableHead>
                <TableHead>content-type</TableHead>
                <TableHead>size</TableHead>
                <TableHead>sha256</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mail.attachments.map((attachment, index) => (
                <TableRow key={`${attachment.sha256}-${index}`}>
                  <TableCell className="v">{attachment.filename || '(unnamed)'}</TableCell>
                  <TableCell>{attachment.content_type || '—'}</TableCell>
                  <TableCell className="n">{attachment.size_bytes.toLocaleString('en-US')} bytes</TableCell>
                  <TableCell className="v">
                    <code>{attachment.sha256}</code>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      ) : null}
    </>
  )
}

// #2178: fetchMail (kept above, other pages still call it) resolves null for
// both "this session has no captured body" (backend 404: "no captured mail",
// "mail body not yet imported") and "the request failed outright", because
// serviceJSON collapses statuses. This variant rides serviceJSONResult
// (#1966) so the 404 — a real answer about the session — stays separable
// from a gateway/timeout failure, which these two inline viewers now render
// differently. Its handler never rejects, so callers need no catch.
type MailFetch = { state: 'mail'; mail: Mail } | { state: 'missing' } | { state: 'failed' }

const fetchMailDetailed = createServerFn({ method: 'GET' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<MailFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<Mail>(`/api/v1/mail/${encodeURIComponent(data.id)}`)
    if (result.ok) return { state: 'mail', mail: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

/** Fetches on demand and renders the message inline.
 *
 *  Deferred rather than loaded with the page because the body lives in a
 *  separate index behind a two-step join, and a list of sessions would
 *  otherwise pay for every message an operator never opens. */
export function CapturedMailInline({ sessionId }: { sessionId: string }) {
  const [busy, setBusy] = useState(false)
  const [mail, setMail] = useState<Mail | 'missing' | 'failed' | null>(null)
  const [opened, setOpened] = useState(false)

  const load = async () => {
    setOpened(true)
    // A past 'failed' attempt is refetchable; anything else is a settled
    // answer we cache so re-opening doesn't cost another round-trip.
    if (mail !== null && mail !== 'failed') return
    setBusy(true)
    try {
      const result = await fetchMailDetailed({ data: { id: sessionId } })
      setMail(result.state === 'mail' ? result.mail : result.state)
    } finally {
      setBusy(false)
    }
  }

  if (!opened) {
    return (
      <Button variant="secondary" size="sm" type="button" onClick={load}>
        Show captured message
      </Button>
    )
  }
  if (busy) return <Skeleton className="h-4 w-full" aria-hidden="true" />
  if (mail === 'failed') {
    return (
      <ErrorStateBlock
        title="The captured message failed to load"
        hint="The backend request failed — this is not evidence either way about whether a body was captured."
        onRetry={() => void load()}
      />
    )
  }
  if (mail === 'missing' || mail === null) {
    return <p className="empty">No captured mail body found for this session.</p>
  }
  return <MailMessage mail={mail} />
}

/** The session page's framed version — same message, its own card. */
export function MailCard({ sessionId }: { sessionId: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [mail, setMail] = useState<Mail | 'missing' | 'failed' | null>(null)

  const load = async () => {
    if (mail !== null && mail !== 'failed') return
    setBusy(true)
    try {
      const result = await fetchMailDetailed({ data: { id: sessionId } })
      setMail(result.state === 'mail' ? result.mail : result.state)
    } finally {
      setBusy(false)
    }
  }

  const toggle = async () => {
    if (open) {
      setOpen(false)
      return
    }
    setOpen(true)
    await load()
  }

  return (
      <Card id="captured-mail">
        <CardContent>
          <h2>Captured mail</h2>
          <p className="text-sm text-muted-foreground">
        The SMTP DATA body mailoney captured for this session, parsed to headers and plain text. An HTML body is decoded to
        text but never rendered, and attachments are listed as metadata only — no bytes are stored or downloadable here.
      </p>
      <Button variant="secondary" size="sm" type="button" onClick={toggle} disabled={busy}>
        {busy ? 'Loading…' : open ? 'Hide mail' : 'View mail'}
      </Button>
      {open ? (
        busy ? (
          <Skeleton className="h-4 w-full" aria-hidden="true" />
        ) : mail === 'failed' ? (
          <ErrorStateBlock
            title="The captured message failed to load"
            hint="The backend request failed — this is not evidence either way about whether a body was captured."
            onRetry={() => void load()}
          />
        ) : mail === 'missing' || mail === null ? (
          <p className="empty">No captured mail body found for this session.</p>
        ) : (
          <MailMessage mail={mail} />
        )
      ) : null}
        </CardContent>
      </Card>
  )
}
