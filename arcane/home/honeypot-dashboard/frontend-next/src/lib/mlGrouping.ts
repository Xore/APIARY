// Collapsing near-duplicate ML anomaly rows (#1566).
//
// The ml-worker scores each event independently, so one burst from one
// address produces one row per event. Measured on the live index: 66% of all
// 7,305 anomalies sit in an (address, same second) bucket with siblings, and
// the worst single burst is 48 rows for one IP inside one second, every one
// of them scoring exactly 0.8000. Paging through that is reading the same
// sentence forty-eight times.
//
// This only became possible once the store's sort was fixed in the same
// change: the list was previously ordered by a field the documents do not
// have, so a burst arrived scattered through the page rather than contiguous,
// and there were no runs to collapse.
//
// Scope, deliberately: runs are collapsed *within the fetched page*. The
// alternative is an aggregation in the Rust tier, which would change the
// shape of the shared /api/v1/store endpoint for every other consumer. A
// burst longer than the page still splits across the boundary, so the badge
// says how many rows were folded together here rather than claiming to be
// the size of the whole burst.

import type { StoreRow } from '../components/StoreList'

/** How far two composite scores may differ and still count as the same finding. */
export const SCORE_EPSILON = 0.01

/** Rows folded into this one, including itself. Absent means an ungrouped row. */
export const DUPES = '_dupes'
/** Every `_doc_id` folded into this row, so an acknowledgement covers them all. */
export const DUPE_IDS = '_dupe_ids'

function second(row: StoreRow): string {
  const raw = typeof row['@timestamp'] === 'string' ? (row['@timestamp'] as string) : ''
  // "2026-08-24T20:59:23.138Z" -> "2026-08-24T20:59:23"; a value with no
  // sub-second part is already truncated and slicing it is harmless.
  return raw.slice(0, 19)
}

function score(row: StoreRow): number {
  const raw = row['composite_score']
  return typeof raw === 'number' ? raw : Number.NaN
}

function docId(row: StoreRow): string {
  return typeof row['_doc_id'] === 'string' ? (row['_doc_id'] as string) : ''
}

/**
 * Fold consecutive near-identical rows into one, carrying the count and the
 * ids that went into it.
 *
 * "Consecutive" is what makes this correct without a global view: the rows
 * arrive newest-first by `@timestamp`, so every member of a burst is adjacent
 * to the rest of it. A row that merely resembles one three pages away is left
 * alone, which is the honest outcome — it is not part of the same moment.
 *
 * Comparison is against the run's representative rather than the previous
 * row, so a slow drift of 0.009 per row cannot chain an arbitrarily wide
 * range of scores into a single group.
 */
export function collapseRuns(rows: StoreRow[]): StoreRow[] {
  const out: StoreRow[] = []
  for (const row of rows) {
    const head = out[out.length - 1]
    const sameRun =
      head !== undefined &&
      head['src_ip'] === row['src_ip'] &&
      second(head) === second(row) &&
      Math.abs(score(head) - score(row)) <= SCORE_EPSILON &&
      // NaN scores never compare equal, so a row with no score is never
      // folded into another — it is genuinely a different kind of finding.
      !Number.isNaN(score(head)) &&
      !Number.isNaN(score(row))

    if (sameRun) {
      head[DUPES] = ((head[DUPES] as number) ?? 1) + 1
      ;(head[DUPE_IDS] as string[]).push(docId(row))
      continue
    }
    out.push({ ...row, [DUPES]: 1, [DUPE_IDS]: [docId(row)] })
  }
  return out
}

/** Ids an action on this row should apply to — the group, or just the row. */
export function idsFor(row: StoreRow): string[] {
  const ids = row[DUPE_IDS]
  if (Array.isArray(ids) && ids.length) return ids as string[]
  return [docId(row)].filter(Boolean)
}

/** How many rows this one stands for. 1 when it stands only for itself. */
export function foldedCount(row: StoreRow): number {
  const count = row[DUPES]
  return typeof count === 'number' && count > 0 ? count : 1
}
