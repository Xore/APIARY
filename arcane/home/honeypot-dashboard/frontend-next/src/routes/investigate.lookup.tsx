// Hash / IOC lookup — #1577: clusters.tsx's "ES →" link into
// /investigate/cluster only reaches whatever made the precomputed top-250
// attacker-clusters-v1 leaderboard (correlator.rs's fetch_cluster_aggregates
// cap). An operator with an arbitrary payload hash, TLS/SSH fingerprint, ASN
// or provider name from outside that leaderboard had no route in that
// reached the same cross-source correlation view. This page is that route:
// classify what was typed and jump straight to the existing correlation
// backend (investigate.rs's cidr/cluster handlers) — no new correlation
// logic, just a front door for it.
//
// Free-text IOCs (a domain or URL pulled from a payload) are deliberately
// NOT handled here: the old dashboard/ioc_correlation.go this issue named
// was a single-sample floss-vs-sandbox cross-reference embedded in the
// ghidra page, never a fleet-wide "has this domain shown up anywhere"
// index — that capability doesn't exist on either dashboard, so this page
// says so instead of faking a search with no backend behind it.
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV4_CIDR = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/
const IPV6_CIDR = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*\/\d{1,3}$/
const ASN = /^AS\d+$/i
const HASH = /^[0-9a-fA-F]{12,64}$/

type Shape =
  | { kind: 'ip'; value: string }
  | { kind: 'cidr'; value: string }
  | { kind: 'asn'; value: string }
  | { kind: 'hash'; value: string }
  | { kind: 'provider'; value: string }

function classify(raw: string): Shape {
  const value = raw.trim()
  if (IPV4.test(value) || IPV6.test(value)) return { kind: 'ip', value }
  if (IPV4_CIDR.test(value) || IPV6_CIDR.test(value)) return { kind: 'cidr', value }
  if (ASN.test(value)) return { kind: 'asn', value: value.toUpperCase() }
  if (HASH.test(value)) return { kind: 'hash', value: value.toLowerCase() }
  return { kind: 'provider', value }
}

// A hash could be a payload's canonical_shasum or a fingerprint (JA3/JA4/
// SSH pubkey) — investigate.rs's cluster_membership_filter needs to know
// which. Try payload first (the more common lookup — a captured file's
// hash), fall back to fingerprint; a caller who knows better can still
// reach either kind directly from clusters.tsx's own links.
const resolveHashKind = createServerFn({ method: 'GET' })
  .inputValidator((input: { value: string }) => input)
  .handler(async ({ data }): Promise<'payload' | 'fingerprint' | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    for (const kind of ['payload', 'fingerprint'] as const) {
      const params = new URLSearchParams({ kind, value: data.value })
      const hit = await serviceJSON<{ ip_count: number }>(`/api/v1/investigate/cluster?${params.toString()}`)
      if (hit) return kind
    }
    return null
  })

export const Route = createFileRoute('/investigate/lookup')({
  component: Lookup,
})

function Lookup() {
  const navigate = useNavigate()
  const [value, setValue] = useState('')
  const [status, setStatus] = useState<'idle' | 'busy' | 'not-found'>('idle')
  const [lastHash, setLastHash] = useState('')

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const shape = classify(value)
    setStatus('busy')
    switch (shape.kind) {
      case 'ip':
        await navigate({ to: '/investigate/ip/$ip', params: { ip: shape.value } })
        return
      case 'cidr':
        await navigate({ to: '/investigate/cidr/$cidr', params: { cidr: shape.value } })
        return
      case 'asn':
        await navigate({ to: '/investigate/cluster', search: { kind: 'asn', value: shape.value } })
        return
      case 'provider':
        await navigate({ to: '/investigate/cluster', search: { kind: 'provider', value: shape.value } })
        return
      case 'hash': {
        const resolved = await resolveHashKind({ data: { value: shape.value } })
        if (!resolved) {
          setLastHash(shape.value)
          setStatus('not-found')
          return
        }
        await navigate({ to: '/investigate/cluster', search: { kind: resolved, value: shape.value } })
        return
      }
    }
  }

  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Hash / IOC lookup"
        subtitle="Paste an IP, CIDR, ASN, provider name, payload hash, or connection fingerprint to jump straight into its cross-source correlation view — including values outside the clusters/campaigns leaderboards."
      />
      <form className="card" onSubmit={submit}>
        <div className="filters">
          <input
            className="search"
            style={{ flex: 1 }}
            placeholder="203.0.113.7, 203.0.113.0/24, AS64500, a hex payload hash or fingerprint…"
            aria-label="Value to look up"
            value={value}
            onChange={(event) => {
              setValue(event.target.value)
              setStatus('idle')
            }}
            autoFocus
          />
          <button className="copy" type="submit" disabled={!value.trim() || status === 'busy'}>
            {status === 'busy' ? 'Looking up…' : 'Look up'}
          </button>
        </div>
      </form>
      {status === 'not-found' ? (
        <p className="empty" role="status" aria-live="polite">
          No cluster correlation for <code>{lastHash}</code> as either a payload hash or a fingerprint — it may be
          real but below the correlation floor (fewer than two source IPs). If it's a captured file, its own
          analysis is still reachable directly at{' '}
          <a className="lnk" href={`/payload-analysis/${lastHash}`}>
            /payload-analysis/{lastHash}
          </a>
          .
        </p>
      ) : null}
      <p className="note">
        A domain or URL pulled from a payload isn't correlated fleet-wide here — that's a per-sample
        floss-vs-sandbox cross-reference on the payload's own Ghidra/workbench page, not a searchable index across
        every capture.
      </p>
    </>
  )
}
