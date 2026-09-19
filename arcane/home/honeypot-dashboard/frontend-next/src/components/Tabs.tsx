// Accessible tab strip — the port of hp-app.js's dashboard-tab handling
// (activateDashboardTab's roving tabIndex + the Arrow/Home/End keydown
// cycler at hp-app.js:1131-1148) as a reusable component, so every page
// that lost its tablist in the port gets the full semantics back:
// aria-controls/id linkage, roving focus, arrow-key cycling. Now using
// shadcn Tabs internally while preserving the same API.
import { Tabs as ShadcnTabs, TabsList as ShadcnTabsList, TabsTrigger as ShadcnTabsTrigger, TabsContent as ShadcnTabsContent } from './ui/tabs'

export type TabDef = { id: string; label: React.ReactNode }

export function Tabs({
  tabs,
  active,
  onSelect,
  label,
  className = 'segmented',
  idPrefix = 'tab',
}: {
  tabs: TabDef[]
  active: string
  onSelect: (id: string) => void
  /** Accessible name for the tablist. */
  label: string
  className?: string
  /** Prefix for tab/panel element ids — must match TabPanel's. */
  idPrefix?: string
}) {
  return (
    <ShadcnTabs value={active} onValueChange={onSelect}>
      <ShadcnTabsList className={className} aria-label={label}>
        {tabs.map((tab) => (
          <ShadcnTabsTrigger
            key={tab.id}
            value={tab.id}
            id={`${idPrefix}-${tab.id}`}
            className={tab.id === active ? 'active' : undefined}
          >
            {tab.label}
          </ShadcnTabsTrigger>
        ))}
      </ShadcnTabsList>
    </ShadcnTabs>
  )
}

export function TabPanel({
  id,
  active,
  idPrefix = 'tab',
  children,
  className,
}: {
  id: string
  active: string
  idPrefix?: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <ShadcnTabsContent
      value={id}
      id={`${idPrefix}-panel-${id}`}
      className={className}
      hidden={id !== active}
    >
      {children}
    </ShadcnTabsContent>
  )
}
