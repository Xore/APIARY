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
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'

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
  .inputValidator((input: { id: string }) => input)
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
      <table className="data-table" style={{ marginTop: 12 }}>
        <tbody>
          <tr>
            <td>From</td>
            <td className="v">{mail.from ? formatAddress(mail.from) : '—'}</td>
          </tr>
          <tr>
            <td>To</td>
            <td className="v">{mail.to.length ? mail.to.map(formatAddress).join(', ') : '—'}</td>
          </tr>
          <tr>
            <td>Subject</td>
            <td className="v">{mail.subject || '—'}</td>
          </tr>
          <tr>
            <td>Date</td>
            <td>{mail.date || '—'}</td>
          </tr>
          <tr>
            <td>Message-ID</td>
            <td className="v">{mail.message_id || '—'}</td>
          </tr>
          <tr>
            <td>Size</td>
            <td className="n">{mail.size_bytes.toLocaleString('en-US')} bytes</td>
          </tr>
        </tbody>
      </table>
      <p className="subtitle">Body</p>
      <pre className="code">{mail.body_text || '(empty body)'}</pre>
      {mail.attachments.length > 0 ? (
        <>
          <p className="subtitle">Attachments</p>
          <table className="data-table">
            <thead>
              <tr>
                <th>filename</th>
                <th>content-type</th>
                <th>size</th>
                <th>sha256</th>
              </tr>
            </thead>
            <tbody>
              {mail.attachments.map((attachment, index) => (
                <tr key={`${attachment.sha256}-${index}`}>
                  <td className="v">{attachment.filename || '(unnamed)'}</td>
                  <td>{attachment.content_type || '—'}</td>
                  <td className="n">{attachment.size_bytes.toLocaleString('en-US')} bytes</td>
                  <td className="v">
                    <code>{attachment.sha256}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </>
  )
}

/** Fetches on demand and renders the message inline.
 *
 *  Deferred rather than loaded with the page because the body lives in a
 *  separate index behind a two-step join, and a list of sessions would
 *  otherwise pay for every message an operator never opens. */
export function CapturedMailInline({ sessionId }: { sessionId: string }) {
  const [busy, setBusy] = useState(false)
  const [mail, setMail] = useState<Mail | null | 'missing'>(null)
  const [opened, setOpened] = useState(false)

  const load = async () => {
    setOpened(true)
    if (mail !== null) return
    setBusy(true)
    try {
      const result = await fetchMail({ data: { id: sessionId } })
      setMail(result ?? 'missing')
    } finally {
      setBusy(false)
    }
  }

  if (!opened) {
    return (
      <button className="btn btn-secondary btn-sm" type="button" onClick={load}>
        Show captured message
      </button>
    )
  }
  if (busy) return <span className="skeleton-line" aria-hidden="true" />
  if (mail === 'missing' || mail === null) {
    return <p className="empty">No captured mail body found for this session.</p>
  }
  return <MailMessage mail={mail} />
}

/** The session page's framed version — same message, its own card. */
export function MailCard({ sessionId }: { sessionId: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [mail, setMail] = useState<Mail | null | 'missing'>(null)

  const toggle = async () => {
    if (open) {
      setOpen(false)
      return
    }
    setOpen(true)
    if (mail !== null) return
    setBusy(true)
    try {
      const result = await fetchMail({ data: { id: sessionId } })
      setMail(result ?? 'missing')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card wide" id="captured-mail">
      <h2>Captured mail</h2>
      <p className="note">
        The SMTP DATA body mailoney captured for this session, parsed to headers and plain text. An HTML body is decoded to
        text but never rendered, and attachments are listed as metadata only — no bytes are stored or downloadable here.
      </p>
      <button className="btn btn-secondary btn-sm" type="button" onClick={toggle} disabled={busy}>
        {busy ? 'Loading…' : open ? 'Hide mail' : 'View mail'}
      </button>
      {open ? (
        busy ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : mail === 'missing' || mail === null ? (
          <p className="empty">No captured mail body found for this session.</p>
        ) : (
          <MailMessage mail={mail} />
        )
      ) : null}
    </div>
  )
}
