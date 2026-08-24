// What each sensor actually captured, in that sensor's own terms (#1856).
//
// The sensor detail page had three hand-written views for three sensors,
// while twenty-six sensors produce events. Writing twenty-three more by
// hand would fix today and rot tomorrow: the next sensor deployed would be
// invisible again, which is exactly how the page reached the state the
// issue describes.
//
// So this is a spec, not a set of components. A sensor gets a curated
// reading of its own protocol where we know the protocol, and a complete
// reading of its own fields where we do not — never nothing. A sensor
// added upstream shows up in the catalog aggregation by construction and
// renders through the generic path until someone teaches it a protocol
// here, which is a smaller, later, optional job rather than a
// prerequisite for it being visible at all.
//
// Field names come from the shipped documents, not from the sensors'
// upstream docs — several sensors disagree with their own documentation
// about what they emit, and the index is the authority on what is there.

import { type Json, type JsonRecord } from './json'

export type SensorEventRow = {
  when: string
  src_ip: string
  src_port: number
  dst_port: number
  /** The sensor's own honeypot.* object, untouched. `JsonRecord` rather
   *  than `unknown` values so a server function can prove it serializes. */
  fields: JsonRecord
}

/** A field, or the first of several names different versions use for it. */
export type FieldRef = string | string[]

export type ProtocolColumn = {
  header: string
  field: FieldRef
  /** Render as code — identifiers, paths, raw protocol tokens. */
  mono?: boolean
  /** Render as a badge in this tone when non-empty. */
  badge?: 'danger' | 'warning' | 'success' | 'muted' | 'info'
}

export type ProtocolSpec = {
  /** One phrase: what this sensor is and what it captures. */
  what: string
  /** Columns beyond the time / source / port every sensor shares. */
  columns: ProtocolColumn[]
  /** The characteristic artefact — the thing worth running the sensor for. */
  artefacts: { label: string; field: FieldRef }[]
  /** A field holding a session id, linked to the session record. */
  sessionField?: FieldRef
  /** Fields holding a payload hash, linked to the payload record. */
  hashFields?: FieldRef[]
}

/** Fields every sensor carries about the deployment rather than the attack.
 *
 *  Hidden from the generic field dump because twenty rows of persona and
 *  site metadata bury the four rows that say what happened. Nothing is
 *  dropped from the record itself — the raw JSON is always one row away. */
export const DEPLOYMENT_FIELDS = new Set([
  'asset_id',
  'organization',
  'persona_id',
  'site_id',
  'sensor',
  'sensorid',
  'sensorName',
  'name',
  'timestamp',
  'time',
  'eventTime',
  'event_timestamp',
  'src_ip',
  'src_port',
  'srcIP',
  'srcPort',
  'srcHost',
  'dst_ip',
  'dst_port',
  'port',
  'public_ip',
  'internal_probe',
  'id',
  'uuid',
  'event_uuid',
  'created_by_node_id',
  'level',
])

const SSH: ProtocolSpec = {
  what: 'SSH and telnet sessions — the credentials tried and the commands run',
  columns: [
    { header: 'event', field: 'eventid', mono: true },
    { header: 'protocol', field: 'protocol' },
    { header: 'what happened', field: 'message' },
  ],
  artefacts: [{ label: 'Session line', field: 'message' }],
  sessionField: 'session',
}

const ICS: ProtocolSpec = {
  what: 'Industrial control protocol — the request an attacker sent and the response the emulated device served',
  columns: [
    { header: 'protocol', field: 'data_type', badge: 'info' },
    { header: 'event', field: 'event_type', mono: true },
  ],
  artefacts: [
    { label: 'Request', field: 'request' },
    { label: 'Response served', field: 'response' },
  ],
}

const HTTP_LIKE: ProtocolSpec = {
  what: 'HTTP requests against an emulated appliance — path, headers, and the response served',
  columns: [
    { header: 'request', field: ['path', 'url'], mono: true },
    { header: 'event', field: 'event', mono: true },
    { header: 'user agent', field: 'user_agent' },
  ],
  artefacts: [
    { label: 'Headers', field: 'headers' },
    { label: 'Message', field: 'message' },
  ],
}

/** Sensor name → how to read it. Prefix keys ending in `*` match a family. */
export const PROTOCOLS: Record<string, ProtocolSpec> = {
  cowrie: SSH,
  beelzebub: {
    what: 'Multi-protocol deception — what the emulated service was asked for',
    columns: [
      { header: 'protocol', field: 'protocol', badge: 'info' },
      { header: 'request', field: 'path', mono: true },
      { header: 'status', field: 'status' },
    ],
    artefacts: [{ label: 'What the sensor recorded', field: 'msg' }],
  },
  dionaea: {
    what: 'Service emulation — SMB, FTP, MSSQL, MySQL, SIP and MQTT exchanges, and the malware they drop',
    columns: [
      { header: 'what', field: 'origin', mono: true },
      { header: 'protocol', field: ['data.connection.protocol', 'connection.protocol'], badge: 'info' },
    ],
    artefacts: [{ label: 'Captured exchange', field: 'data' }],
    hashFields: ['data.file.sha512', 'data.file.md5hash', 'md5hash', 'sha512'],
  },
  multipot: {
    what: 'Low-interaction catch-all — the bytes a client sent before anything answered',
    columns: [
      { header: 'event', field: 'event', mono: true },
      { header: 'protocol', field: 'proto', badge: 'info' },
      { header: 'client', field: 'client' },
    ],
    artefacts: [{ label: 'Captured bytes', field: 'data' }],
    sessionField: 'session',
  },
  sentrypeer: {
    what: 'SIP / VoIP fraud probing — the SIP request exactly as it arrived',
    columns: [
      { header: 'method', field: 'sip_method', mono: true },
      { header: 'called number', field: 'called_number', mono: true },
      { header: 'user agent', field: ['sip_user_agent', 'user_agent'] },
    ],
    artefacts: [{ label: 'SIP message', field: 'sip_message' }],
  },
  dnp3: {
    what: 'DNP3 — the function codes requested against the emulated outstation',
    columns: [
      { header: 'event', field: 'event', mono: true },
      { header: 'function', field: 'function', mono: true },
      { header: 'application function', field: 'app_function', mono: true },
    ],
    artefacts: [{ label: 'Raw frame', field: 'frame_hex' }],
  },
  'dns-honeypot': {
    what: 'DNS — the names queried and the record types asked for',
    columns: [
      { header: 'query', field: 'query', mono: true },
      { header: 'type', field: 'qtype', badge: 'info' },
      { header: 'transport', field: 'proto' },
      { header: 'recursion', field: 'rd' },
    ],
    artefacts: [],
  },
  'rdp-honeypot': {
    what: 'RDP — the credentials offered and the security protocols requested',
    columns: [
      { header: 'event', field: 'event', mono: true },
      { header: 'username', field: ['canonical_user', 'username'], mono: true },
      { header: 'password', field: 'canonical_pass', mono: true },
      { header: 'requested protocols', field: 'requested_protocols' },
    ],
    artefacts: [{ label: 'Captured exchange', field: 'data' }],
  },
  dicompot: {
    what: 'DICOM — which application entities tried to talk to the emulated imaging node',
    columns: [
      { header: 'event', field: 'event', mono: true },
      { header: 'calling AE', field: 'calling_ae', mono: true },
      { header: 'called AE', field: 'called_ae', mono: true },
    ],
    artefacts: [],
  },
  galah: {
    what: 'LLM-generated web responses — the full request received and the response served back',
    columns: [
      { header: 'request', field: 'path', mono: true },
      { header: 'user agent', field: 'user_agent' },
    ],
    artefacts: [
      { label: 'Request', field: 'httpRequest' },
      { label: 'Response served', field: 'httpResponse' },
    ],
    hashFields: ['body_sha256'],
  },
  'api-honeypot': {
    what: 'Fake API surface — the calls made against it and the status each got',
    columns: [
      { header: 'request', field: 'path', mono: true },
      { header: 'method', field: 'method', mono: true },
      { header: 'status', field: 'status' },
      { header: 'user agent', field: 'user_agent' },
    ],
    artefacts: [{ label: 'Headers', field: 'headers' }],
  },
  elasticpot: {
    what: 'Elasticsearch emulation — the queries and URLs attackers sent',
    columns: [
      { header: 'url', field: 'url', mono: true },
      { header: 'event', field: 'eventid', mono: true },
    ],
    artefacts: [
      { label: 'Request', field: 'request' },
      { label: 'What the sensor recorded', field: 'message' },
    ],
  },
  wordpot: {
    what: 'WordPress emulation — the plugin, theme and admin paths probed',
    columns: [
      { header: 'request', field: 'path', mono: true },
      { header: 'theme', field: 'theme' },
    ],
    artefacts: [{ label: 'What the sensor recorded', field: 'message' }],
  },
  hellpot: {
    what: 'Tarpit — how long a crawler stayed and how many bytes it swallowed',
    columns: [
      { header: 'request', field: ['path', 'URL'], mono: true },
      { header: 'bytes sent', field: 'BYTES' },
      { header: 'held for', field: 'DURATION' },
      { header: 'user agent', field: ['user_agent', 'USERAGENT'] },
    ],
    artefacts: [{ label: 'What the sensor recorded', field: 'message' }],
  },
  endlessh: {
    what: 'SSH tarpit — how long a client was held on a banner that never ends',
    columns: [
      { header: 'event', field: 'event', mono: true },
      { header: 'held for', field: 'held_ms' },
      { header: 'banner lines', field: 'lines' },
    ],
    artefacts: [],
  },
  canarytokens: {
    what: 'Canarytokens — which planted token fired, and what the trigger carried',
    columns: [
      { header: 'token type', field: 'token_type', badge: 'warning' },
      { header: 'channel', field: 'channel' },
      { header: 'memo', field: 'memo' },
    ],
    artefacts: [
      { label: 'Trigger data', field: 'src_data' },
      { label: 'Additional data', field: 'additional_data' },
    ],
  },
  'citrix-honeypot': HTTP_LIKE,
  'cisco-asa-honeypot': HTTP_LIKE,
  'conpot*': ICS,
}

/** The sensors that have their own hand-written view on this page already. */
export const BESPOKE_SENSORS = new Set(['mailoney', 'http-honeypot', 'tanner'])

/** How to read this sensor, or `null` to fall back to its own fields.
 *
 *  Prefix keys exist because conpot ships one binary per emulated device
 *  (`conpot-s7-1500`, `conpot-iec104`, `conpot-kamstrup`, …) and every one
 *  of them writes the same document shape. Enumerating them would mean a
 *  new profile silently losing its view. */
export function protocolFor(sensor: string): ProtocolSpec | null {
  const exact = PROTOCOLS[sensor]
  if (exact) return exact
  for (const [key, spec] of Object.entries(PROTOCOLS)) {
    if (key.endsWith('*') && sensor.startsWith(key.slice(0, -1))) return spec
  }
  return null
}

/** Read a dotted path, trying each alternative name in order. */
export function readField(fields: JsonRecord, ref: FieldRef): Json | undefined {
  const names = Array.isArray(ref) ? ref : [ref]
  for (const name of names) {
    let value: Json | undefined = fields
    for (const part of name.split('.')) {
      if (value === null || typeof value !== 'object') {
        value = undefined
        break
      }
      value = (value as JsonRecord)[part]
    }
    if (value !== undefined && value !== null && value !== '') return value
  }
  return undefined
}

/** A field value as one line of text — never `[object Object]`. */
export function fieldText(value: Json | undefined): string {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

/** A field value as a block — pretty JSON for structures, text otherwise. */
export function fieldBlock(value: Json | undefined): string {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

/** The fields worth showing for a sensor with no protocol spec, in a
 *  stable order so the same sensor does not reshuffle between renders. */
export function meaningfulFields(fields: JsonRecord): [string, Json][] {
  return Object.entries(fields)
    .filter(([key, value]) => !DEPLOYMENT_FIELDS.has(key) && value !== null && value !== '')
    .sort(([a], [b]) => a.localeCompare(b))
}
