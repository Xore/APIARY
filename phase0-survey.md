# APIARY #3202 — Phase 0 route + component survey

Surveyed 2026-09-17. This is an inventory only; no migration decisions are made here.

## Scope and counting

`src/routes/` currently contains **46 `.tsx` route modules** (and 70 filesystem
entries total). That differs from the issue/plan's 44-route expectation. The
two modules which make the count 46 are `__root.tsx` (the TanStack root route)
and `index.tsx` (the overview page); both are actual `.tsx` route modules and
are included below. Non-UI `.ts` API/auth/health routes and the two route tests
are outside this inventory.

All UI routes are wrapped by `__root.tsx` → `AppShell`, so the shell's theme
classes apply to every page: `app-content app-content--wide app-main
app-shell__nav-scrim skip-link sr-only`, plus the imported `Sidebar`, `Topbar`,
`CommandPalette`, `LiveToasts`, `ProblemReportButton`, and `SettingsModal`
surfaces listed in the component map.

## Route inventory

`Components` names hand-rolled local components directly imported by the route.
`Route theme.css classes` are literal classes declared in that route (not the
shared component classes below). Dynamic/template-composed class names are not
expanded; their static tokens are included where present.

| Route module | Components | Route theme.css classes |
| --- | --- | --- |
| `__root.tsx` | AppShell | `empty-state empty-state__action empty-state__hint empty-state__icon empty-state__title hp-notfound` |
| `agent-campaigns.tsx` | Investigate, ErrorState, StoreList (type) | `card__scroll chip data-table hp-flow--tight metric metric-grid metric__label metric__value note recent text-muted v` |
| `alerts.tsx` | ConfirmDialog, Investigate, ErrorState, Tabs | `badge badge--muted badge--warning copy dashboard-panel empty lnk note search` |
| `attackers.tsx` | Investigate, EChart, AttackerGraph, ErrorState, Tabs | `badge badge--accent badge--info badge--muted badge--warning btn btn-ghost btn-sm card__footer card__label card__row card__scroll card__value card__value--mono chip dashboard-panel empty hp-token-url lnk note` |
| `auth-events.tsx` | StoreList, Investigate (type) | `badge badge--muted badge--warning card card__scroll data-table half hp-flow metric metric-grid metric__label metric__value n v` |
| `campaigns.tsx` | Investigate, ErrorState | `badge badge--warning card chip data-table lnk n note v wide` |
| `canarytokens.tsx` | StoreList, Investigate, Tabs | `badge badge--info badge--muted btn btn-ghost btn-secondary btn-sm card card__scroll chip dashboard-panel data-table empty empty-state empty-state__divider empty-state__hint empty-state__icon empty-state__title filters form-input hp-head-actions hp-token-url lnk mono note skeleton-line template-card template-card__desc template-card__icon template-card__title template-gallery text-muted v wide` |
| `cape.$sha.tsx` | Investigate, ErrorState | `ago badge badge--muted card card__label card__row card__scroll card__value card__value--mono chip code data-table empty metric metric-grid metric__label metric__value n note section-heading skeleton-line text-danger v wide` |
| `cape.index.tsx` | StoreList, Investigate (type), CardIcons | `badge badge--muted hp-md__preview mono text-muted` |
| `clusters.tsx` | Investigate, ErrorState | `badge badge--muted chip lnk` |
| `commands.tsx` | Investigate, ErrorState | `badge badge--muted chip hp-md__preview note` |
| `credentials.tsx` | Investigate, ErrorState, StoreList | `badge badge--accent badge--muted btn btn-ghost btn-secondary btn-sm card chip empty filters form-input hp-pre-wrap note wide` |
| `dead-letters.tsx` | ConfirmDialog, Investigate, ErrorState, StoreList | `btn btn-danger btn-sm chip copy note search` |
| `event.$id.tsx` | Investigate, ErrorState | `badge badge--muted btn btn-ghost btn-sm card chip code data-table empty note section-link skeleton-line subtitle v wide` |
| `events.tsx` | ErrorState, FiltersModal, Investigate, RowActions | `action-menu badge badge--info badge--muted badge--warning btn btn-ghost btn-primary btn-secondary btn-sm card card__scroll chip code data-table data-table--responsive dropdown empty-state empty-state__action empty-state__hint empty-state__icon empty-state__title eventmeta eventmeta__group eventmeta__label filters form-input form-label hp-feed-break hp-ip-filter-actions hp-ip-filter-count hp-ip-filter-ip hp-ip-filter-list hp-ip-filter-menu hp-ip-filter-row hp-lazy-controls hp-md__close hp-md__list hp-md__pane hp-open-in hp-open-in-heading hp-open-in-menu hp-row-actions-cell is-active label-section lnk mono n note overview-header recent sess settings-field subtitle text-muted v wide` |
| `ghidra.$sha.tsx` | Investigate, ErrorState, ArtifactList, GhidraCallGraph, ConfirmDialog | `alert alert--danger alert--success alert--warning btn btn-secondary btn-sm card card__label card__row card__scroll chip code dashboard-panel data-table empty g hp-ai-citations hp-ai-citations__item hp-ai-citations__item--invalid hp-ai-citations__item--valid hp-ai-citations__label hp-ai-citations__label--invalid hp-ai-citations__label--valid hp-ai-citations__list hp-ai-report hp-ai-report__body hp-chat hp-chat-msg hp-chat-msg__content hp-chat-msg__meta hp-chat-msg__name hp-chat-msg__role hp-figure hp-pre-wrap message metric metric-grid metric__label metric__value note section-heading skeleton-line tabs text-secondary v wide` |
| `github-analysis.$sha.tsx` | ConfirmDialog, Investigate, ErrorState | `alert alert--success badge badge--muted badge--red btn btn-danger btn-ghost btn-secondary btn-sm card card__scroll chip dashboard-panel data-table empty lnk metric metric-grid metric__label metric__value metric__value--text modal modal-backdrop modal__close n note open pdf-viewer-frame pdf-viewer-modal pdf-viewer-title project-card project-card__desc project-card__header project-card__icon project-card__meta project-card__title project-grid section-heading skeleton-line tabs text-danger v wide` |
| `github-analysis.index.tsx` | StoreList, Investigate (type), CardIcons | `badge badge--accent badge--muted hp-md__preview mono text-muted` |
| `history.tsx` | Investigate, ErrorState | `badge badge--muted btn btn-secondary btn-sm chip filters form-input hp-md__preview` |
| `index.tsx` | OverviewPanels, ErrorState, RowActions, EChart | `ago badge badge--info badge--muted btn btn-ghost btn-sm card card__scroll code dashboard-panel data-table empty gen half hp-flow hp-hero hp-hero__links hp-hero__search hp-hero__status hp-row-actions-cell label-section lnk metric metric-grid metric__label metric__spark metric__value n note recent section-heading section-link sess skeleton-line state status-dot v wide` |
| `investigate.cidr.$cidr.tsx` | Investigate | `badge badge--muted card card__scroll chip data-table half hp-md__preview metric metric-grid metric__label metric__value n note v` |
| `investigate.cluster.tsx` | Investigate | `badge badge--muted card card__scroll chip data-table half hp-md__preview metric metric-grid metric__label metric__value n note v` |
| `investigate.ip.$ip.tsx` | Investigate, ErrorState, Tabs | `badge badge--danger badge--info badge--muted btn btn-danger btn-secondary btn-sm card card__scroll chip dashboard-panel data-table empty half hp-input hp-md__preview hp-num hp-row metric metric-grid metric__label metric__value n note recent v wide` |
| `investigate.lookup.tsx` | Investigate | `card copy empty filters hp-grow lnk note search text-danger` |
| `ips.tsx` | Investigate, OverviewPanels, ErrorState | `badge badge--info btn btn-secondary btn-sm card chip hp-lazy-controls hp-src-card hp-src-card__head hp-src-card__ip hp-src-card__sensors hp-src-card__stats hp-src-card__when hp-src-grid skeleton-line wide` |
| `kill-chain.tsx` | Investigate, EChart | `card chip note wide` |
| `llm-analysis.tsx` | StoreList, Investigate (type) | `badge badge--info badge--muted btn btn-secondary btn-sm card card__scroll data-table empty filters form-input n note text-muted v wide` |
| `ml-anomalies.tsx` | StoreList, Investigate, ErrorState, ConfirmDialog, EChart, FiltersModal | `badge badge--danger badge--info badge--muted badge--success badge--warning btn btn-secondary btn-sm card card__scroll chip data-table empty filters form-input form-label metric metric-grid metric__label metric__value n note settings-field skeleton-line text-muted v wide` |
| `payload-analysis.$hash.tsx` | ConfirmDialog, Investigate, ErrorState, RowActions | `action-menu action-menu__item action-menu__popover badge badge--danger badge--green badge--muted badge--red btn btn-danger btn-ghost btn-primary btn-secondary btn-sm card card__label card__row card__scroll card__value card__value--mono chip code dashboard-panel data-table empty filters half hp-code-results hp-pl-info-popover hp-pl-info-row hp-pl-label-trigger hp-push-end k lnk metric metric-grid metric__label metric__value metric__value--text modal modal-backdrop modal__close n note open pdf-viewer-frame pdf-viewer-modal pdf-viewer-title search section-heading skeleton-line table-scroll tabs text-danger v wide` |
| `payload-workbench.results.tsx` | ConfirmDialog, Investigate, ArtifactList, ErrorState, CardIcons | `badge badge--danger badge--muted badge--warning btn btn-danger btn-primary btn-secondary btn-sm card chip dashboard-panel data-table empty filters form-input hp-field hp-field--wide hp-flow hp-flow--tight hp-md__preview hp-push-end label-section lnk mono n note project-card project-card__badges project-card__header project-card__meta project-card__title project-grid skeleton-line state table-scroll text-danger text-muted v wb-option-grid wb-options wide` |
| `payloads.tsx` | ConfirmDialog, ErrorState, Investigate, RowActions | `badge badge--muted btn btn-secondary btn-sm card chip code empty hp-card-link hp-code-results hp-flow--tight hp-lazy-controls mono note project-card project-card__badges project-card__desc project-card__header project-card__icon project-card__meta project-card__title project-grid skeleton-line wide` |
| `problem-reports.tsx` | Investigate, StoreList | `badge badge--muted btn btn-ghost btn-secondary btn-sm data-table hp-md__preview n note table-scroll text-muted v` |
| `recordings.tsx` | Investigate, ErrorState | `badge badge--info btn btn-secondary btn-sm chip hp-md__preview lnk sess skeleton-line subtitle` |
| `reports.tsx` | Investigate, ErrorState, CardIcons | `badge badge--muted btn btn-danger btn-ghost btn-primary btn-secondary btn-sm card chip dashboard-panel data-table empty empty-state empty-state__divider empty-state__hint empty-state__icon empty-state__title filters form-input hp-field hp-field--wide hp-flow hp-num hp-rp-actions hp-rp-payload-badges hp-rp-payload-results hp-rp-payload-row hp-rp-progress hp-rp-progress__position hp-rp-progress__steps hp-rp-review hp-rp-review__key hp-rp-review__row hp-rp-review__value hp-rp-row-actions hp-rp-status hp-rp-swatch hp-rp-swatch--dark hp-rp-swatch--light hp-rp-tag hp-rp-tag--light hp-rp-template hp-rp-templates hp-rp-theme label-section modal modal-backdrop modal__close note open pdf-viewer-frame pdf-viewer-modal pdf-viewer-title skeleton-line table-scroll template-card template-card__desc template-card__icon template-card__title template-gallery text-muted v wide` |
| `revdeck.$sha.tsx` | Investigate, ErrorState | `badge badge--muted card card__scroll chip code data-table empty note skeleton-line v wide` |
| `revdeck.index.tsx` | StoreList, Investigate (type), CardIcons | `badge badge--muted hp-md__preview text-muted` |
| `sandbox.$job.tsx` | ArtifactList, ConfirmDialog, Investigate, ErrorState | `alert alert--danger badge badge--muted badge--warning btn btn-danger btn-sm card card__label card__row card__scroll card__value card__value--mono chip code dashboard-panel data-table empty filters half hp-flow metric metric-grid metric__label metric__value mono n note section-heading skeleton-line tabs text-danger v wide` |
| `sandbox.vnc.tsx` | Investigate | `card chip empty hp-vnc-canvas-wrap hp-vnc-status skeleton-line wide` |
| `search.tsx` | Investigate, ErrorState | `btn btn-secondary btn-sm card chip data-table empty-state filters form-input half lnk n note skeleton-line v wide` |
| `sensors.$sensor.tsx` | Investigate, ErrorState, SensorEvents, CuratedSensorViews | `card chip data-table empty lnk metric metric-grid metric__label metric__spark metric__trend metric__value n note progress skeleton-line subtitle text-danger v wide` |
| `sensors.index.tsx` | — | — |
| `sessions.$id.tsx` | Investigate, CapturedMail, ErrorState | `badge badge--muted card card__scroll chip data-table half hp-md__preview n note v wide` |
| `settings.tsx` | ConfirmDialog, ErrorState, EsHistoryConsole, StoreList, ThemeGallery | `active ago badge badge--muted btn btn-danger btn-ghost btn-primary btn-secondary btn-sm card card__label card__row card__value code data-table empty empty-state__divider filters form-input form-label hp-field hp-flow hp-flow--tight hp-settings-column hp-settings-head hp-settings-pane is-dirty label-section metric metric-grid metric__label metric__value modal__close n note segmented settings-actions settings-field settings-field__desc settings-grid settings-layout settings-layout__content settings-layout__sidebar sidebar__item sidebar__search sidebar__section-label skeleton-line switch table-scroll v` |
| `source-health.tsx` | Investigate, ErrorState | `card card__label card__row card__value card__value--mono chip data-table half hp-flow--loose metric metric-grid metric__label metric__value note section-heading section-link state v wide` |
| `topology.tsx` | EChart, ErrorState, Investigate | `card chip data-table half hp-flow--loose note section-heading text-muted v wide` |
| `tty-replay.$shasum.tsx` | Investigate, ErrorState, Tabs | `btn btn-primary btn-secondary btn-sm card card__scroll chip code dashboard-panel data-table empty filters half hp-flow hp-tty-controls hp-tty-status hp-tty-term label-section lnk metric metric-grid metric__label metric__value n note overview-header skeleton-line subtitle timeline-block timeline-block__meta timeline-track v wide` |

## Consumed component theme.css class map

These are literal classes emitted by local components imported above; combine a
route's row with its named component rows and the shell classes. Components
with no classes either emit SVG only or are type-only imports.

| Component | theme.css classes |
| --- | --- |
| AppShell | `app-content app-content--wide app-main app-shell__nav-scrim skip-link sr-only` |
| ArtifactList | `badge badge--muted data-table lnk n skeleton-line subtitle v` |
| AttackerGraph | `note skeleton-line` |
| CapturedMail | `btn btn-secondary btn-sm card code data-table empty hp-flow n note skeleton-line subtitle v wide` |
| CardIcons | — |
| CommandPalette | `command-palette__empty command-palette__field command-palette__results command-palette__row-meta command-palette__row-title modal modal--palette modal-backdrop modal__close open` |
| ConfirmDialog | `btn btn-secondary danger-dialog__warning edit-dialog edit-dialog-backdrop edit-dialog__actions edit-dialog__desc edit-dialog__title open` |
| CuratedSensorViews | `badge badge--danger badge--muted badge--success badge--warning card hp-md__preview label-section note wide` |
| EChart | `chip empty note skeleton-line` |
| ErrorState | `btn btn-ghost btn-sm empty-state empty-state__hint empty-state__icon empty-state__title` |
| EsHistoryConsole | `btn btn-ghost btn-sm card code copy filters hp-field hp-head-actions metric metric-grid metric__label metric__trend metric__value search text-secondary` |
| FiltersModal | `btn btn-primary btn-secondary hp-flow--tight hp-row modal modal--compact modal-backdrop modal__close modal__header open settings-grid` |
| GhidraCallGraph | `empty filters form-input hp-flow--tight note skeleton-line` |
| Investigate | `btn btn-secondary btn-sm card data-table data-table--responsive empty-state empty-state__action empty-state__hint empty-state__icon empty-state__title filters hp-flow hp-lazy-controls hp-md__close hp-md__list hp-md__pane hp-md__rowcard hp-row-actions-cell hp-table-state label-section overview-header project-card project-card__badges project-card__desc project-card__header project-card__icon project-card__meta project-card__title project-grid recent skeleton-line subtitle wide` |
| LiveToasts | `hp-toast hp-toast-stack toast` |
| OverviewPanels | `card__scroll chip data-table empty filters form-input heatmap heatmap__cell heatmap__cells heatmap__label heatmap__legend heatmap__row hp-duo leaflet-map map-shell n note skeleton skeleton-line v` |
| ProblemReportButton | `btn btn-primary btn-secondary form-input hp-fab hp-field hp-flow--tight hp-modal-status hp-pr-modal hp-row hp-row--end modal modal-backdrop modal__close modal__header note open` |
| RowActions | `hp-row-actions__group hp-row-actions__items hp-row-actions__more` |
| SensorEvents | `badge hp-md__preview label-section` |
| SettingsModal | `modal-backdrop open` |
| Sidebar | `app-sidebar app-sidebar__body avatar dropdown dropdown__divider dropdown__item hp-account hp-account-menu hp-account-note hp-brand hp-brand-mark hp-brand-text hp-profile-name hp-sidebar-search sidebar__profile sidebar__recent sidebar__section-label theme-art--dark theme-art--light` |
| StoreList | `chip copy note` |
| Tabs | `segmented` |
| ThemeGallery | `hp-theme-gallery hp-theme-tile hp-theme-tile__accent hp-theme-tile__art hp-theme-tile__body hp-theme-tile__desc hp-theme-tile__label hp-theme-tile__line hp-theme-tile__line--wide hp-theme-tile__sidebar` |
| Topbar | `alert app-toolbar app-toolbar__banner app-toolbar__brand app-toolbar__search avatar btn btn-ghost btn-icon hp-alert-badge hp-crumb hp-toolbar-actions hp-toolbar-avatar sep status-dot theme-art--dark theme-art--light` |

## Special rendering surfaces

| Special | Route render points | Library mount/render point |
| --- | --- | --- |
| ECharts | `routes/index.tsx:688,724,732,740,748,773,783,792,800,810,818,827,835,840,845,850`; `routes/topology.tsx:209`; `routes/kill-chain.tsx:36,41,49`; `routes/ml-anomalies.tsx:806`; `routes/attackers.tsx:236` | `components/EChart.tsx:424` (`echarts.init`), host `:573` |
| xterm | `routes/tty-replay.$shasum.tsx:638` (`TerminalPlayback`) | `routes/tty-replay.$shasum.tsx:230` (`new Terminal`), host `:372` |
| noVNC | `routes/sandbox.vnc.tsx:88` | `routes/sandbox.vnc.tsx:54` (`new RFB`), host `:88` |
| Cytoscape | `routes/attackers.tsx:228` (`AttackerGraph`); `routes/ghidra.$sha.tsx:682` (`GhidraCallGraph`) | `components/AttackerGraph.tsx:53`, host `:152`; `components/GhidraCallGraph.tsx:60`, host `:184` |
| Leaflet | `routes/index.tsx:585`; `routes/ips.tsx:113` (`AttackMap`) | `components/OverviewPanels.tsx:330` (`L.map`), host `:467` |

No decision file was needed. The Phase 4 default remains keep-and-restyle for
these library surfaces.
