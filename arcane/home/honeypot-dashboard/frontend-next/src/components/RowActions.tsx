// The hover-revealed quick actions on a table row (#1868).
//
// These were bare text: `⧁` for copy, `▶` for replay, `👤` for the
// attacker profile. `⧁` is not a copy symbol anyone recognises, and the
// emoji renders in full colour at a different optical weight from every
// other mark in the interface, so the strip read as unfinished next to the
// SVG icons used everywhere else — live, it rendered as the literal string
// "⧁👤".
//
// Two things follow from putting them here rather than inline. The actions
// are drawn the same way on every surface that has them, instead of two
// hand-rolled copies drifting apart. And each one carries a real
// accessible name, which a lone glyph in a link never did.
//
// `.hp-row-actions` in the stylesheet already provides the 24x24 button
// surface and the hover reveal; this is what goes inside it.
import type React from 'react'

const ICON_PROPS = {
  width: 14,
  height: 14,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const

function Icon({ children }: { children: React.ReactNode }) {
  return <svg {...ICON_PROPS}>{children}</svg>
}

export const RowIcons = {
  copy: (
    <Icon>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </Icon>
  ),
  replay: (
    <Icon>
      <polygon points="6 4 20 12 6 20 6 4" />
    </Icon>
  ),
  profile: (
    <Icon>
      <circle cx="12" cy="8" r="3.5" />
      <path d="M4.5 20a7.5 7.5 0 0 1 15 0" />
    </Icon>
  ),
  /** A page, opened. The action that says "everything behind this row". */
  detail: (
    <Icon>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <polyline points="14 3 14 8 19 8" />
      <line x1="9" y1="13" x2="15" y2="13" />
      <line x1="9" y1="17" x2="13" y2="17" />
    </Icon>
  ),
  payload: (
    <Icon>
      <path d="M21 8v8a2 2 0 0 1-1 1.73l-7 4a2 2 0 0 1-2 0l-7-4A2 2 0 0 1 3 16V8a2 2 0 0 1 1-1.73l7-4a2 2 0 0 1 2 0l7 4A2 2 0 0 1 21 8z" />
      <polyline points="3.3 7 12 12 20.7 7" />
      <line x1="12" y1="22" x2="12" y2="12" />
    </Icon>
  ),
  evebox: (
    <Icon>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </Icon>
  ),
  kibana: (
    <Icon>
      <line x1="12" y1="20" x2="12" y2="10" />
      <line x1="18" y1="20" x2="18" y2="4" />
      <line x1="6" y1="20" x2="6" y2="16" />
    </Icon>
  ),
  /** A category of destinations, for the "open in" group. */
  openIn: (
    <Icon>
      <path d="M15 3h6v6" />
      <path d="M10 14 21 3" />
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
    </Icon>
  ),
  arkime: (
    <Icon>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </Icon>
  ),
} as const

export type RowAction = {
  /** The accessible name. Also the tooltip — one label, one meaning. */
  label: string
  icon: React.ReactNode
  /** A link action. */
  href?: string
  /** A button action. */
  onClick?: () => void
  /** Opens outside the dashboard. */
  external?: boolean
}

/** A named set of actions that opens beside its own icon.
 *
 *  For a category rather than a single action -- "open in", with the
 *  external tools inside it. Its members appear next to the trigger when
 *  the pointer or focus arrives, so nothing is behind a click and nothing
 *  claims width it is not using. */
export type RowActionGroup = {
  label: string
  icon: React.ReactNode
  actions: (RowAction | null | undefined)[]
}

function Control({ action }: { action: RowAction }) {
  const shared = {
    title: action.label,
    'aria-label': action.label,
  }
  return action.href ? (
    <a
      href={action.href}
      {...shared}
      {...(action.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
      // The row itself opens the inspector; an action must not also do that
      // on its way to somewhere else.
      onClick={(event) => event.stopPropagation()}
    >
      {action.icon}
    </a>
  ) : (
    <button
      type="button"
      {...shared}
      onClick={(event) => {
        event.stopPropagation()
        action.onClick?.()
      }}
    >
      {action.icon}
    </button>
  )
}

/** The strip. Renders nothing when there is nothing to offer, so a surface
 *  never shows an empty pill.
 *
 *  #1898: the first action rests on screen and the rest arrive on approach.
 *  The strip used to be `opacity: 0` until the row was hovered, which made
 *  every action discoverable only by accident -- nothing on screen
 *  suggested that hovering would reveal anything, so a reader concludes the
 *  column is empty. It is solid at rest now; what collapses is the width of
 *  the extras, not the existence of the strip. */
export function RowActions({
  actions,
  groups = [],
}: {
  actions: (RowAction | null | undefined)[]
  groups?: (RowActionGroup | null | undefined)[]
}) {
  const present = actions.filter((action): action is RowAction => Boolean(action))
  const liveGroups = groups
    .filter((group): group is RowActionGroup => Boolean(group))
    .map((group) => ({
      ...group,
      actions: group.actions.filter((action): action is RowAction => Boolean(action)),
    }))
    .filter((group) => group.actions.length > 0)

  if (present.length === 0 && liveGroups.length === 0) return null

  const [first, ...rest] = present
  return (
    <div className="hp-row-actions">
      {first ? <Control action={first} /> : null}
      {rest.length > 0 || liveGroups.length > 0 ? (
        <span className="hp-row-actions__more">
          {rest.map((action) => (
            <Control key={action.label} action={action} />
          ))}
          {liveGroups.map((group) => (
            <span className="hp-row-actions__group" key={group.label}>
              {/* aria-expanded describes a set that opens on hover and
                  focus rather than on click, so it is never false while the
                  members are reachable -- it is the group's own state, not
                  a button's. */}
              <span role="img" aria-label={group.label} title={group.label} aria-expanded="false">
                {group.icon}
              </span>
              <span className="hp-row-actions__items">
                {group.actions.map((action) => (
                  <Control key={action.label} action={action} />
                ))}
              </span>
            </span>
          ))}
        </span>
      ) : null}
    </div>
  )
}
