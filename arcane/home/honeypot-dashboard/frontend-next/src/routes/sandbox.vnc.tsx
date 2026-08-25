// Sandbox live view — a read-only view of the isolated Windows guest while
// a captured sample detonates (#805). Ports dashboard/sandbox_vnc.go +
// static/hp-sandbox-vnc.js: this tier never touches libvirt or the VNC
// stream itself, it only reports whether a Windows-sandbox detonation is
// currently running and where the operator-configured bridge WebSocket
// lives (SANDBOX_VNC_BRIDGE_WS) — the browser's noVNC client (@novnc/novnc,
// a real npm dependency here rather than Go's vendored copy) connects to
// that bridge directly. viewOnly is client-side belt-and-suspenders; the
// real enforcement is the bridge's own RFB message filtering, which drops
// KeyEvent/PointerEvent/ClientCutText before they ever reach the VM
// regardless of what any browser-side code does or fails to do.
//
// Admin-gated at the BFF, same posture as every other admin action in
// this port — watching a live malware detonation is at least as sensitive
// as downloading its capture.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'

type VncStatus = { sha256: string; bridge_ws: string }

const fetchVncStatus = createServerFn({ method: 'GET' }).handler(async (): Promise<{ status: VncStatus | null; error: string | null }> => {
  const { serviceFetch } = await import('../lib/backend.server')
  const response = await serviceFetch('/api/v1/sandbox/vnc', undefined, { mounted: true })
  if (!response.ok) return { status: null, error: await response.text() }
  return { status: (await response.json()) as VncStatus, error: null }
})

export const Route = createFileRoute('/sandbox/vnc')({
  loader: async () => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    return { user, result: fetchVncStatus() }
  },
  component: SandboxVnc,
})

type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error'

function VncViewer({ bridgeWs }: { bridgeWs: string }) {
  const targetRef = useRef<HTMLDivElement>(null)
  const [state, setState] = useState<ConnectionState>('connecting')
  const [message, setMessage] = useState('Connecting to the read-only bridge…')

  useEffect(() => {
    const target = targetRef.current
    if (!target) return
    let disposed = false
    let rfb: InstanceType<typeof import('@novnc/novnc').default> | null = null
    ;(async () => {
      const RFB = (await import('@novnc/novnc')).default
      if (disposed) return
      rfb = new RFB(target, bridgeWs, { shared: true })
      rfb.viewOnly = true
      rfb.scaleViewport = true
      rfb.addEventListener('connect', () => {
        setState('connected')
        setMessage('Connected — view only.')
      })
      rfb.addEventListener('disconnect', (event) => {
        const clean = (event as CustomEvent<{ clean?: boolean }>).detail?.clean
        setState('disconnected')
        setMessage(clean ? 'Disconnected.' : 'Connection lost — the detonation may have finished, or the bridge is unreachable.')
      })
      rfb.addEventListener('credentialsrequired', () => {
        setState('error')
        setMessage('This bridge does not support authenticated VNC sessions.')
      })
      rfb.addEventListener('securityfailure', (event) => {
        const reason = (event as CustomEvent<{ reason?: string }>).detail?.reason
        setState('error')
        setMessage(`Security handshake failed: ${reason || 'unknown reason'}`)
      })
    })()
    return () => {
      disposed = true
      rfb?.disconnect()
    }
  }, [bridgeWs])

  return (
    <div className="card wide" data-vnc-state={state}>
      <div className="hp-vnc-status" role="status">
        {message}
      </div>
      <div className="hp-vnc-canvas-wrap">
        <div ref={targetRef} aria-busy={state === 'connecting'}>
          {state === 'connecting' ? <span className="skeleton-line" aria-hidden="true" /> : null}
        </div>
      </div>
    </div>
  )
}

function SandboxVnc() {
  const { user, result } = Route.useLoaderData()
  const [status, setStatus] = useState<VncStatus | 'loading' | 'error'>('loading')
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    result.then((outcome) => {
      if (cancelled) return
      if (outcome.status) setStatus(outcome.status)
      else {
        setStatus('error')
        setError(outcome.error || 'The VNC bridge is not available.')
      }
    })
    return () => {
      cancelled = true
    }
  }, [result])

  const isAdmin = !user || user.role === 'admin'
  if (!isAdmin) {
    return (
      <InvestigateHeader label="Live detonation" title="Sandbox view — view only" subtitle="Admin role required to watch a live detonation." />
    )
  }

  return (
    <>
      <InvestigateHeader
        label="Live detonation"
        title="Sandbox view — view only"
        subtitle={
          status !== 'loading' && status !== 'error'
            ? `A live, read-only view of the isolated Windows guest while sample ${status.sha256} detonates. Nothing here can send keyboard, mouse, or clipboard input to the VM — enforced by the bridge itself, not by this page.`
            : 'A live, read-only view of the isolated Windows guest while a captured sample detonates.'
        }
        chips={
          status !== 'loading' && status !== 'error' ? (
            <>
              <Link className="chip" to="/payload-workbench/results" hash="sandbox">
                ← sandbox results
              </Link>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: status.sha256 }}>
                static analysis
              </Link>
            </>
          ) : undefined
        }
      />
      {status === 'loading' ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : status === 'error' ? (
        <div className="card wide">
          <p className="empty">{error}</p>
        </div>
      ) : (
        <VncViewer bridgeWs={status.bridge_ws} />
      )}
    </>
  )
}
