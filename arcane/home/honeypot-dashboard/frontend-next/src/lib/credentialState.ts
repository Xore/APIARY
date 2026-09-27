// The API's side of #3213's three credential questions, as one phrase.
//
// The backend stopped sending a password and started sending three answers
// that used to be conflated into it: was a credential there, could we read
// it, and did anything authenticate. This module is where those become
// words, and it is deliberately a pure function with no React in it so the
// vocabulary is testable on its own -- the failure this guards against is
// "unknown" quietly rendering as "none", which looks correct on screen and
// is a lie about the attacker.
//
// Three rules, and they are the whole point:
//
//   1. `unknown` is never rendered as `absent`. The sensor reports unknown
//      when a channel that could have carried a credential was not read in
//      full -- a body over the read cap, an IKE exchange with no login at
//      all. "We did not see one" and "we could not tell" are different
//      claims and the cell has to keep them apart.
//   2. The bait-credential indicator is an ATTEMPT against this fleet's own
//      fictional values. Not a vendor default list, not access, not a
//      bypass, not a CVE -- the wording here is the only place that claim is
//      made, so it is worded as a match and nothing more.
//   3. An empty `credential_status` means the event predates the schema. The
//      API removed the password from it, so the cell must not then report
//      "no credential" -- that would be the service describing its own
//      redaction as an observation about the attack.

/** The `honeypot.credential_status` values the two decoys emit. */
export type CredentialStatus = 'absent' | 'present_unparsed' | 'extracted' | 'unknown'

/** The `honeypot.auth_outcome` values the two decoys emit. */
export type AuthOutcome = 'simulated' | 'real' | 'unknown'

/** The subset of a request row this module reads. */
export type CredentialFacts = {
  username?: string
  auth_type?: string
  credential_status?: string
  credential_present?: boolean | null
  credential_indicator_match?: boolean
  auth_outcome?: string
}

export type CredentialState = {
  /** The account half, when there was one. Never a secret. */
  account: string
  /** The whole cell, or '' when there is genuinely nothing to say. */
  label: string
  /** Badge tone to render with. */
  tone: 'muted' | 'warning' | 'danger' | 'info'
  /** An attempt used this decoy's own bait credential. An attempt. */
  indicatorMatched: boolean
  /**
   * The presence boolean exactly as the sensor reported it. `null` means the
   * sensor never said, which is NOT the same answer as `false`.
   */
  present: boolean | null
}

const STATUS_PHRASE: Record<string, string> = {
  absent: 'no credential',
  present_unparsed: 'credential present, not parsed',
  extracted: 'credential extracted',
  unknown: 'credential unknown',
}

const AUTH_PHRASE: Record<string, string> = {
  simulated: 'auth simulated',
  real: 'auth real',
  unknown: 'auth unknown',
}

/**
 * Describes one request's credential outcome.
 *
 * Unknown status strings render as themselves rather than being swallowed by
 * a default: a sensor that grows a fifth state should show up on screen as
 * the new word, not as a blank cell that reads like "nothing happened".
 */
export function describeCredentialState(row: CredentialFacts): CredentialState {
  const account = row.username ?? ''
  const status = row.credential_status ?? ''
  const present = row.credential_present ?? null
  const indicatorMatched = row.credential_indicator_match === true
  const auth = row.auth_outcome ?? ''

  let phrase: string
  if (status === '') {
    // Pre-schema document. See rule 3 above.
    phrase = 'credentials removed'
  } else {
    phrase = STATUS_PHRASE[status] ?? status
  }

  const parts = [account, phrase]
  if (indicatorMatched) parts.push('bait credential attempted')
  if (auth !== '') parts.push(AUTH_PHRASE[auth] ?? `auth ${auth}`)
  if (account !== '' && row.auth_type) parts.push(`via ${row.auth_type}`)

  return {
    account,
    label: parts.filter(Boolean).join(' · '),
    tone: indicatorMatched ? 'danger' : status === 'extracted' || status === 'present_unparsed' ? 'warning' : 'muted',
    indicatorMatched,
    present,
  }
}
