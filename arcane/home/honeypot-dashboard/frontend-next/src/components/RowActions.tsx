// Shared row actions with accessible names and consistent SVG icons.
import { Fragment, type ReactNode } from 'react'
import { Button } from './ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'

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

function Icon({ children }: { children: ReactNode }) {
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
  /** Down into something. "Give me the bytes." */
  download: (
    <Icon>
      <path d="M12 3v12" />
      <polyline points="7 10 12 15 17 10" />
      <path d="M5 20h14" />
    </Icon>
  ),
  /** Instruments on a bench: the analysis you assemble yourself. */
  workbench: (
    <Icon>
      <path d="M4 5h16" />
      <path d="M9 5v6a4 4 0 0 0 6 0V5" />
      <path d="M12 15v5" />
      <path d="M8 20h8" />
    </Icon>
  ),
  /** A list of things that happened. */
  events: (
    <Icon>
      <line x1="9" y1="7" x2="20" y2="7" />
      <line x1="9" y1="12" x2="20" y2="12" />
      <line x1="9" y1="17" x2="20" y2="17" />
      <circle cx="5" cy="7" r="1.2" />
      <circle cx="5" cy="12" r="1.2" />
      <circle cx="5" cy="17" r="1.2" />
    </Icon>
  ),
  /** Out of here, to somewhere public. */
  publish: (
    <Icon>
      <path d="M12 19V6" />
      <polyline points="7 11 12 6 17 11" />
      <path d="M5 20h14" />
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
  icon: ReactNode
  /** A link action. */
  href?: string
  /** A button action. */
  onClick?: () => void
  /** Opens outside the dashboard. */
  external?: boolean
  /** Does something irreversible, and should not look like its neighbours.
   *
   *  Every other control in a strip navigates or copies, so they are
   *  uniform by design -- which is exactly what makes an action that
   *  publishes or deletes unsafe to sit among them unmarked. */
  danger?: boolean
}

/** A named set of related menu actions. */
export type RowActionGroup = {
  label: string
  icon: ReactNode
  actions: (RowAction | null | undefined)[]
}

function Control({ action }: { action: RowAction }) {
  const className = action.danger ? 'text-destructive hover:text-destructive' : undefined
  return action.href ? (
    <Button asChild variant="ghost" size="icon" className={className}>
      <a
        href={action.href}
        title={action.label}
        aria-label={action.label}
        {...(action.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
        // The row itself opens the inspector; an action must not also do that
        // on its way to somewhere else.
        onClick={(event) => event.stopPropagation()}
      >
        {action.icon}
      </a>
    </Button>
  ) : (
    <Button
      variant="ghost"
      size="icon"
      type="button"
      className={className}
      title={action.label}
      aria-label={action.label}
      onClick={(event) => {
        event.stopPropagation()
        action.onClick?.()
      }}
    >
      {action.icon}
    </Button>
  )
}

function MenuItem({ action }: { action: RowAction }) {
  const className = action.danger ? 'text-destructive focus:text-destructive' : undefined
  return action.href ? (
    <DropdownMenuItem asChild className={className}>
      <a
        href={action.href}
        {...(action.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
        onClick={(event) => event.stopPropagation()}
      >
        {action.icon}
        <span>{action.label}</span>
      </a>
    </DropdownMenuItem>
  ) : (
    <DropdownMenuItem
      className={className}
      onSelect={(event) => {
        event.stopPropagation()
        action.onClick?.()
      }}
    >
      {action.icon}
      <span>{action.label}</span>
    </DropdownMenuItem>
  )
}

/** Renders nothing when there are no available actions. */
export function RowActions({
  actions,
  groups = [],
  expanded = false,
}: {
  actions: (RowAction | null | undefined)[]
  groups?: (RowActionGroup | null | undefined)[]
  /** Show every ungrouped action instead of collapsing extras into the menu. */
  expanded?: boolean
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
  const visible = expanded ? present : first ? [first] : []
  const menuActions = expanded ? [] : rest
  return (
    <div className="inline-flex items-center gap-0.5">
      {visible.map((action) => <Control key={action.label} action={action} />)}
      {menuActions.length > 0 || liveGroups.length > 0 ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              type="button"
              aria-label="More actions"
              title="More actions"
              onClick={(event) => event.stopPropagation()}
            >
              <Icon>
                <circle cx="5" cy="12" r="1" fill="currentColor" stroke="none" />
                <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
                <circle cx="19" cy="12" r="1" fill="currentColor" stroke="none" />
              </Icon>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" onClick={(event) => event.stopPropagation()}>
            {menuActions.map((action) => <MenuItem key={action.label} action={action} />)}
            {liveGroups.map((group, index) => (
              <Fragment key={group.label}>
                {menuActions.length > 0 || index > 0 ? <DropdownMenuSeparator /> : null}
                <DropdownMenuLabel className="flex items-center gap-2">
                  {group.icon}
                  <span>{group.label}</span>
                </DropdownMenuLabel>
                {group.actions.map((action) => <MenuItem key={action.label} action={action} />)}
              </Fragment>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </div>
  )
}
