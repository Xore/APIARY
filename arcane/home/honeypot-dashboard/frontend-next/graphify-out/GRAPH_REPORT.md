# Graph Report - frontend-next  (2026-09-18)

## Corpus Check
- 205 files · ~196,431 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1888 nodes · 4536 edges · 107 communities (95 shown, 10 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 62 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e79cfa6a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- routeTree.gen.ts
- canarytokens.tsx
- reports.tsx
- settings.tsx
- index.tsx
- formatTimestamp
- getSession
- payload-workbench.results.tsx
- @tanstack/react-router
- auth.ts
- backend.server.ts
- events.tsx
- ips.tsx
- ghidra.$sha.tsx
- confirmAction
- react
- fake-backend.mjs
- package.json
- ErrorState.tsx
- dependencies
- oidc.server.ts
- vitest
- ml-anomalies.tsx
- tty-replay.$shasum.tsx
- sidebar.tsx
- payload-analysis.$hash.tsx
- prefs.ts
- alerts.tsx
- cn
- start.ts
- sensorProtocols.ts
- sandbox.$job.tsx
- EChart.tsx
- compilerOptions
- obs.server.ts
- Commands
- components.json
- dashboard.spec.ts
- AppShell.tsx
- sensors.$sensor.tsx
- proxyToRust
- topology.tsx
- devDependencies
- recent.ts
- LiveToasts.tsx
- Topbar.tsx
- lib/live.ts
- payloads.tsx
- SKILL.md
- Customization & Theming
- @tanstack/react-start
- __root.tsx
- reauth.ts
- login.ts
- Component Composition
- Styling & Customization
- Tools
- CuratedSensorViews.tsx
- mlGrouping.ts
- github-analysis.$sha.tsx
- Results
- sessions.$id.tsx
- shadcn/ui
- sheet.tsx
- CapturedMail.tsx
- cape.$sha.tsx
- sessionGate.server.ts
- credentials.tsx
- -routeShape.test.ts
- start-dashboard.mjs
- button.tsx
- appearanceCookie.ts
- source-health.tsx
- Registry Authoring and Addresses
- Base vs Radix
- Chat & Messaging
- scripts
- cssVar.ts
- PayloadAnalysis
- revdeck.$sha.tsx
- Forms & Inputs
- Critical Rules
- GhidraCallGraph.tsx
- themes.ts
- RowActions.tsx
- empty.tsx
- search.tsx
- sandbox.vnc.tsx
- frontend-next
- ConfirmDialog.tsx
- EsHistoryConsole.tsx
- -alerts.test.tsx
- router.tsx
- vite.config.ts
- utils.ts
- RFB
- prefs.test.ts
- logout.test.ts
- @playwright/test
- bootScript.test.ts
- sensors.index.tsx
- pnpm
- @novnc/novnc
- cluster.mjs
- SESSION_COOKIE_NAME

## God Nodes (most connected - your core abstractions)
1. `react` - 88 edges
2. `cn()` - 88 edges
3. `@tanstack/react-router` - 77 edges
4. `formatTimestamp()` - 75 edges
5. `FileRoutesByPath` - 66 edges
6. `@tanstack/react-start` - 60 edges
7. `getSessionUser` - 42 edges
8. `ErrorStateBlock()` - 38 edges
9. `InvestigateHeader()` - 38 edges
10. `Column` - 28 edges

## Surprising Connections (you probably didn't know these)
- `serviceTokenGate()` --calls--> `assertOidcDisabledPolicy()`  [EXTRACTED]
  server/plugins/service-token-gate.ts → src/lib/oidc.server.ts
- `serviceTokenGate()` --calls--> `assertServiceTokenPolicy()`  [EXTRACTED]
  server/plugins/service-token-gate.ts → src/lib/serviceToken.server.ts
- `clock()` --calls--> `formatTimestamp()`  [EXTRACTED]
  src/components/CuratedSensorViews.tsx → src/lib/time.ts
- `CardFooter` --calls--> `cn()`  [EXTRACTED]
  src/components/ui/card.tsx → src/lib/utils.ts
- `EmptyContent()` --calls--> `cn()`  [EXTRACTED]
  src/components/ui/empty.tsx → src/lib/utils.ts

## Import Cycles
- None detected.

## Communities (107 total, 10 thin omitted)

### Community 0 - "routeTree.gen.ts"
Cohesion: 0.02
Nodes (104): Route, Route, Route, Route, fetchCredReuse, Route, Route, Route (+96 more)

### Community 1 - "canarytokens.tsx"
Cohesion: 0.08
Nodes (45): Column, sha256Of(), StoreListPage(), StorePage, StoreRow, str(), when(), pathString() (+37 more)

### Community 2 - "reports.tsx"
Cohesion: 0.06
Nodes (52): ReportIcon, emit(), getNarrowQuery(), getServerSnapshot(), getSnapshot(), listeners, Registration, SidebarViewTabs() (+44 more)

### Community 3 - "settings.tsx"
Cohesion: 0.05
Nodes (53): ADMIN_PANES, AdminConfig, AUDIT_ACTIONS, AuditEvent, AuditLogCard(), AuditResponse, BANNER_SEVERITIES, BehaviorConfig (+45 more)

### Community 4 - "index.tsx"
Cohesion: 0.05
Nodes (46): leaflet, CommandPalette(), Group, Hit, openCommandPalette(), Row, searchFn, SearchResult (+38 more)

### Community 5 - "formatTimestamp"
Cohesion: 0.06
Nodes (37): TabDef, TabPanel(), Tabs(), copyWithFlash(), formatTimestamp(), readTimePrefs(), TimePrefs, AttackerRow (+29 more)

### Community 6 - "getSession"
Cohesion: 0.13
Nodes (33): backendURL(), ConcurrencyLimiter, elMonitor, envInt(), EVENT_LOOP_LAG_SHED_MS, limitedStreamProxy(), getSession(), redis() (+25 more)

### Community 7 - "payload-workbench.results.tsx"
Cohesion: 0.06
Nodes (37): CodeIcon, FileIcon, ICON_PROPS, SandboxIcon, ShieldIcon, WorkbenchIcon, AnalyzersResponse, CatalogFetch (+29 more)

### Community 8 - "@tanstack/react-router"
Cohesion: 0.07
Nodes (27): @tanstack/react-router, DEFAULT_EMPTY, EmptyState, InvestigateHeader(), MasterDetailTable(), JsonRecord, COLUMNS, EventRow (+19 more)

### Community 9 - "auth.ts"
Cohesion: 0.10
Nodes (35): AccountActions, getSessionUser, fetchLiveToastPrefs, pushAppearancePreference, createCredential, CredentialActions(), linkCredentialToken, rotateCredential (+27 more)

### Community 10 - "backend.server.ts"
Cohesion: 0.08
Nodes (32): ioredis, fetchArtifacts, fetchGraph, backendLimiter, bffInternalURL(), cacheRedis(), currentRequestId(), outcomeOf() (+24 more)

### Community 11 - "events.tsx"
Cohesion: 0.09
Nodes (29): RFC-2606, FiltersButton(), FiltersModal(), SkeletonRows(), clock(), CorrelatedIp, EventFilters, EventMeta() (+21 more)

### Community 12 - "ips.tsx"
Cohesion: 0.10
Nodes (25): countryName(), displayNames, usePaginatedList(), useResolved(), COLUMNS, Commands(), EventRow, fetchCommands (+17 more)

### Community 13 - "ghidra.$sha.tsx"
Cohesion: 0.06
Nodes (22): Annotations, Capa, ChatMessage, ChatThreads, Citation, CryptoHit, Floss, FuzzyHashes (+14 more)

### Community 14 - "confirmAction"
Cohesion: 0.12
Nodes (29): confirmAction(), writeTimePrefs(), fetchPage, Page(), purgeDeadLetters, applyPrefSideEffects(), BehaviorCard(), behaviorForm() (+21 more)

### Community 15 - "react"
Cohesion: 0.11
Nodes (23): react, Alert, AlertDescription, AlertTitle, alertVariants, Table, TableBody, TableCaption (+15 more)

### Community 16 - "fake-backend.mjs"
Cohesion: 0.09
Nodes (25): attackPage, campaignRow, catchAllWarned, clusterPage, credReuseEdges, dashboard, DEAD_LETTERS, eventRow() (+17 more)

### Community 17 - "package.json"
Cohesion: 0.07
Nodes (26): engines, npm, imports, name, private, type, clsx, echarts (+18 more)

### Community 18 - "ErrorState.tsx"
Cohesion: 0.12
Nodes (21): ArtifactList(), ArtifactRow, AttackerGraph(), Graph, GraphEdge, GraphNode, ErrorStateBlock(), ServerQuery (+13 more)

### Community 19 - "dependencies"
Cohesion: 0.08
Nodes (26): dependencies, class-variance-authority, clsx, cytoscape, echarts, ioredis, leaflet, lucide-react (+18 more)

### Community 20 - "oidc.server.ts"
Cohesion: 0.17
Nodes (19): openid-client, getAccountActions, crossOriginResponse(), hasSameOriginHeader(), isSameOriginRequest(), SAFE_METHODS, accountConsoleActions(), allowInsecureOidc() (+11 more)

### Community 21 - "vitest"
Cohesion: 0.14
Nodes (13): vitest, serviceTokenGate(), assertOidcDisabledPolicy(), OIDC_DISABLED_GATE_CODE, oidcDisabledPolicy(), assertServiceTokenPolicy(), DEV_UNAUTH_OVERRIDE_ENV, SERVICE_TOKEN_GATE_CODE (+5 more)

### Community 22 - "ml-anomalies.tsx"
Cohesion: 0.12
Nodes (25): num(), AckControl(), AckRecord, Backlog, buildColumns(), Disposition, dispositionBadge(), DispositionControl() (+17 more)

### Community 23 - "tty-replay.$shasum.tsx"
Cohesion: 0.10
Nodes (20): @xterm/addon-fit, @xterm/xterm, AttackerTab(), base64ToBytes(), fetchProfile, fetchReplay, fetchSourceIp, IpProfile (+12 more)

### Community 24 - "sidebar.tsx"
Cohesion: 0.10
Nodes (23): Sidebar, SidebarContext, SidebarContextProps, SidebarFooter, SidebarGroupAction, SidebarGroupContent, SidebarHeader, SidebarInput (+15 more)

### Community 25 - "payload-analysis.$hash.tsx"
Cohesion: 0.09
Nodes (21): Correlation, CorrelationFetch, DecodedItem, DetailFetch, fetchDetail, fetchGoldenImageStatus, GhidraView, GithubView (+13 more)

### Community 26 - "prefs.ts"
Cohesion: 0.22
Nodes (22): ThemeGallery(), Tile(), Appearance, applyPalette(), applyTheme(), cycleTheme(), emit(), fetchAppearance (+14 more)

### Community 27 - "alerts.tsx"
Cohesion: 0.17
Nodes (17): Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle, Input, Skeleton() (+9 more)

### Community 28 - "cn"
Cohesion: 0.18
Nodes (18): Avatar, AvatarFallback, AvatarImage, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioItem (+10 more)

### Community 29 - "start.ts"
Cohesion: 0.14
Nodes (15): ROOT, buildCsp(), createCspNonce(), CspRuntime, globalScope, storage, withCspScope(), ./lib/cspNonce.server (+7 more)

### Community 30 - "sensorProtocols.ts"
Cohesion: 0.18
Nodes (19): block(), buildColumns(), SensorEventsTable(), BESPOKE_SENSORS, DEPLOYMENT_FIELDS, fieldBlock(), FieldRef, fieldText() (+11 more)

### Community 31 - "sandbox.$job.tsx"
Cohesion: 0.16
Nodes (14): countMap(), Diff, fetchRun, flag(), lineDifference(), lines(), normalizeLine(), normalizeProcess() (+6 more)

### Community 32 - "EChart.tsx"
Cohesion: 0.15
Nodes (15): BarPayload, Builder, builders, ChartKind, EChart(), HeatmapPayload, PiePayload, RadarPayload (+7 more)

### Community 33 - "compilerOptions"
Cohesion: 0.11
Nodes (18): compilerOptions, allowImportingTsExtensions, jsx, lib, module, moduleResolution, noEmit, noFallthroughCasesInSwitch (+10 more)

### Community 34 - "obs.server.ts"
Cohesion: 0.18
Nodes (15): appendNamedEventLine(), counters, eventLoopLagP99(), flushNamedEventSink(), inc(), lagMonitor, logFile(), recordBackendCall() (+7 more)

### Community 35 - "Commands"
Cohesion: 0.12
Nodes (17): `add` — Add components, `apply` — Apply a preset to an existing project, `build` — Build a custom registry, Commands, Contents, `diff` — Check for updates, `docs` — Get component documentation URLs, Dry-Run Mode (+9 more)

### Community 36 - "components.json"
Cohesion: 0.12
Nodes (15): aliases, components, hooks, lib, ui, utils, iconLibrary, rsc (+7 more)

### Community 37 - "dashboard.spec.ts"
Cohesion: 0.18
Nodes (10): BROKEN_MARKERS, NAV_ROUTES, seedSessionCookie(), fixtureSid(), redisSet(), seedFixtureSessions(), SESSION_COOKIE_NAME, IP_TABS (+2 more)

### Community 38 - "AppShell.tsx"
Cohesion: 0.18
Nodes (12): ActionEntry, ApiCallEntry, ProblemReportButton(), pushCapped(), submitReport, SettingsModal(), User, PREDICTIONS (+4 more)

### Community 39 - "sensors.$sensor.tsx"
Cohesion: 0.21
Nodes (13): hasCuratedView(), fetchCatalog, fetchEvents, fetchOverview, Measure, measurePeak(), measureValue(), Overview (+5 more)

### Community 40 - "proxyToRust"
Cohesion: 0.17
Nodes (11): backendMountedURL(), proxyToRust(), eventLoopLagMs(), Overloaded, overloadedResponse(), releaseOnFinish(), recordShed(), proxy() (+3 more)

### Community 41 - "topology.tsx"
Cohesion: 0.18
Nodes (15): containerBadge(), ContainerState, ExposedPort, fetchHealth, fetchServices, fetchTopology, freshnessBadge(), ingressBadge() (+7 more)

### Community 42 - "devDependencies"
Cohesion: 0.13
Nodes (15): devDependencies, jsdom, lru-cache, @playwright/test, tailwindcss, @tailwindcss/vite, @tanstack/router-cli, @types/leaflet (+7 more)

### Community 43 - "recent.ts"
Cohesion: 0.21
Nodes (14): AppShell(), Sidebar(), navHrefFor(), EMPTY, hrefForRecent(), labelForRecent(), listeners, read() (+6 more)

### Community 44 - "LiveToasts.tsx"
Cohesion: 0.19
Nodes (13): Condition, conditionsFrom(), DEFAULT_PREFS, fetchSourceHealth, LiveToasts(), SensorHealth, Severity, SourceHealth (+5 more)

### Community 45 - "Topbar.tsx"
Cohesion: 0.23
Nodes (13): fetchOpenAlertCount, Topbar(), useOpenAlertCount(), isLivePaused(), useLiveInterval(), NAV_SECTIONS, NavItem, NavSection (+5 more)

### Community 46 - "lib/live.ts"
Cohesion: 0.17
Nodes (13): LiveToggle(), getSnapshot(), listeners, LiveEventHandler, LiveState, restorePaused(), serverSnapshot, state (+5 more)

### Community 47 - "payloads.tsx"
Cohesion: 0.19
Nodes (13): boundedFamily(), collectBadges(), fetchGithubVerdicts, fetchPayloads, fetchSourceCounts, GithubBadge, Page, PayloadCard() (+5 more)

### Community 48 - "SKILL.md"
Cohesion: 0.21
Nodes (4): Icons, Icons in Button use data-icon attribute, No sizing classes on icons inside components, Pass icons as component objects, not string keys

### Community 49 - "Customization & Theming"
Cohesion: 0.14
Nodes (14): 1. Built-in variants, 2. Tailwind classes via `className`, 3. Add a new variant, 4. Wrapper components, Adding Custom Colors, Border Radius, Changing the Theme, Checking for Updates (+6 more)

### Community 50 - "@tanstack/react-start"
Cohesion: 0.18
Nodes (11): @tanstack/react-start, ClusterRow, Clusters(), COLUMNS, fetchClusters, Page, classify(), HashKindFetch (+3 more)

### Community 51 - "__root.tsx"
Cohesion: 0.22
Nodes (11): activeBanner(), BannerView, BehaviorConfig, PresentationConfig, fetchShellConfig, RootDocument(), Route, ShellConfig (+3 more)

### Community 52 - "reauth.ts"
Cohesion: 0.25
Nodes (8): setConnectionHealthy(), beginReauth(), checkSessionAlive(), resetReauthForTests(), sessionAwareFetch(), SessionExpiredError, assign, useSessionWatch()

### Community 53 - "login.ts"
Cohesion: 0.35
Nodes (10): recordNamedEvent(), authErrorPage(), escapeHtml(), providerErrorFrom(), RFC-6749, RFC-6749, createSession(), sessionCookie() (+2 more)

### Community 54 - "Component Composition"
Cohesion: 0.15
Nodes (13): Avatar always needs AvatarFallback, Button has no isPending or isLoading prop, Callouts use Alert, Card structure, Choosing between overlay components, Component Composition, Contents, Dialog, Sheet, and Drawer always need a Title (+5 more)

### Community 55 - "Styling & Customization"
Cohesion: 0.15
Nodes (13): Built-in variants first, className for layout only, Contents, No manual dark: color overrides, No manual z-index on overlay components, No raw color values for status/state indicators, No space-x-* / space-y-*, Prefer size-* over w-* h-* when equal (+5 more)

### Community 56 - "Tools"
Cohesion: 0.17
Nodes (11): Configuring Registries, Setup, `shadcn:get_add_command_for_items`, `shadcn:get_audit_checklist`, `shadcn:get_item_examples_from_registries`, `shadcn:get_project_registries`, `shadcn:list_items_in_registries`, shadcn MCP Server (+3 more)

### Community 57 - "CuratedSensorViews.tsx"
Cohesion: 0.18
Nodes (10): clock(), CuratedSensorView(), fetchSensors, HTTP_COLUMNS, HttpRequest, MAILONEY_COLUMNS, MailoneySession, SensorDetail (+2 more)

### Community 58 - "mlGrouping.ts"
Cohesion: 0.27
Nodes (9): collapseRuns(), docId(), DUPE_IDS, DUPES, foldedCount(), idsFor(), score(), SCORE_EPSILON (+1 more)

### Community 59 - "github-analysis.$sha.tsx"
Cohesion: 0.23
Nodes (10): fetchRun, GithubAnalysisDetail(), GithubAnalysisRun, resubmitAnalysis, Route, RunFetch, Scanner, scannerBadge() (+2 more)

### Community 60 - "Results"
Cohesion: 0.24
Nodes (12): abortGpuJob, childCount(), fetchGhidra, fetchGpuQueue, fetchSandbox, fetchStatic, fetchWorkbench, fetchYara (+4 more)

### Community 61 - "sessions.$id.tsx"
Cohesion: 0.20
Nodes (10): EVENT_COLUMNS, EventRow, fetchSession, hasCapturedMail(), Kv, Sequence, SessionDetail, SessionFetch (+2 more)

### Community 62 - "shadcn/ui"
Cohesion: 0.18
Nodes (11): Component Docs, Examples, and Usage, Component Selection, Current Project Context, Detailed References, Key Fields, Key Patterns, Principles, Quick Reference (+3 more)

### Community 63 - "sheet.tsx"
Cohesion: 0.20
Nodes (10): lucide-react, @radix-ui/react-dialog, SheetContent, SheetContentProps, SheetDescription, SheetFooter(), SheetHeader(), SheetOverlay (+2 more)

### Community 64 - "CapturedMail.tsx"
Cohesion: 0.24
Nodes (10): CapturedMailInline(), fetchMail, fetchMailDetailed, formatAddress(), Mail, MailAddress, MailAttachment, MailCard() (+2 more)

### Community 65 - "cape.$sha.tsx"
Cohesion: 0.24
Nodes (9): Json, CapeDetail(), CapeRun, fetchRun, ReportSummary, Route, RunFetch, scoreDisplay() (+1 more)

### Community 66 - "sessionGate.server.ts"
Cohesion: 0.25
Nodes (8): oidcDisabled(), isPublicFn(), PUBLIC_FN_FILES, resolveFunctionUser(), getSession, REQUEST, SESSION, unauthenticatedResponse()

### Community 67 - "credentials.tsx"
Cohesion: 0.27
Nodes (10): buildColumns(), CredentialRecord, CredentialsResponse, fetchCredentials, fetchLinkableTokens, linkedBadge(), Page(), ProvisionForm() (+2 more)

### Community 68 - "-routeShape.test.ts"
Cohesion: 0.20
Nodes (7): collectRouteShape(), walk(), COMPONENTS, EXPECTED_ROUTE_SHAPE, ROUTES, RouteShape, tsxSources()

### Community 69 - "start-dashboard.mjs"
Cohesion: 0.24
Nodes (5): getFreePort(), startFakeRedis(), children, PORT, ROOT

### Community 70 - "button.tsx"
Cohesion: 0.24
Nodes (8): class-variance-authority, @radix-ui/react-slot, Badge(), BadgeProps, badgeVariants, Button, ButtonProps, buttonVariants

### Community 71 - "appearanceCookie.ts"
Cohesion: 0.38
Nodes (8): Appearance, APPEARANCE_COOKIE, parseAppearance(), readAppearanceCookie(), resolveMode(), serialiseAppearance(), writeAppearanceCookie(), getAppearance

### Community 72 - "source-health.tsx"
Cohesion: 0.27
Nodes (7): clusterBadge(), COLUMNS, formatBytes(), formatDuration(), SensorHealth, SourceHealth, SourceHealthPage()

### Community 73 - "Registry Authoring and Addresses"
Cohesion: 0.22
Nodes (9): Address Schemes, Build and Verify, GitHub Registries, Include, Item Definitions, Mental Model, Registry Authoring and Addresses, Registry Dependencies (+1 more)

### Community 74 - "Base vs Radix"
Cohesion: 0.22
Nodes (9): Accordion, Base vs Radix, Button / trigger as non-button element (base only), Composition: asChild (radix) vs render (base), Contents, Select, Select — multiple selection and object values (base only), Slider (+1 more)

### Community 75 - "Chat & Messaging"
Cohesion: 0.22
Nodes (9): Attachments use Attachment, Chat & Messaging, Contents, Escape hatch: the scroller hooks, Message rows use Message, Message surfaces use Bubble, Scrollable threads use MessageScroller, Streaming, anchoring, and jump-to-latest are built in (+1 more)

### Community 76 - "scripts"
Cohesion: 0.22
Nodes (9): scripts, build, dev, generate-routes, preview, test, test:browser, test:watch (+1 more)

### Community 77 - "cssVar.ts"
Cohesion: 0.36
Nodes (6): cache, cssVar(), currentAppearance(), buildTheme(), chartColor, registerXoreTheme()

### Community 78 - "PayloadAnalysis"
Cohesion: 0.44
Nodes (9): buildStaticView(), buildYaraView(), fetchCorrelation, fetchRelatedEvents, jarr(), jnum(), jobj(), jstr() (+1 more)

### Community 79 - "revdeck.$sha.tsx"
Cohesion: 0.25
Nodes (6): Citation, fetchRun, RevDeckAnalysis, RevdeckDetail(), RevdeckRun, RunFetch

### Community 80 - "Forms & Inputs"
Cohesion: 0.25
Nodes (8): Buttons inside inputs use InputGroup + InputGroupAddon, Contents, Field validation and disabled states, FieldSet + FieldLegend for grouping related fields, Forms & Inputs, Forms use FieldGroup + Field, InputGroup requires InputGroupInput/InputGroupTextarea, Option sets (2–7 choices) use ToggleGroup

### Community 81 - "Critical Rules"
Cohesion: 0.25
Nodes (8): Chat & Messaging → [chat.md](./rules/chat.md), CLI, Component Structure → [composition.md](./rules/composition.md), Critical Rules, Forms & Inputs → [forms.md](./rules/forms.md), Icons → [icons.md](./rules/icons.md), Styling & Tailwind → [styling.md](./rules/styling.md), Use Components, Not Custom Markup → [composition.md](./rules/composition.md)

### Community 82 - "GhidraCallGraph.tsx"
Cohesion: 0.29
Nodes (6): cytoscape, fetchCallGraph, GhidraCallGraph(), Graph, GraphEdge, GraphNode

### Community 83 - "themes.ts"
Cohesion: 0.29
Nodes (6): mapping, DEFAULT_THEME, Theme, THEME_IDS, THEMES, themeSearchTerms()

### Community 84 - "RowActions.tsx"
Cohesion: 0.25
Nodes (5): ICON_PROPS, RowAction, RowActionGroup, RowActions(), RowIcons

### Community 85 - "empty.tsx"
Cohesion: 0.29
Nodes (7): Empty(), EmptyContent(), EmptyDescription(), EmptyHeader(), EmptyMedia(), emptyMediaVariants, EmptyTitle()

### Community 86 - "search.tsx"
Cohesion: 0.29
Nodes (6): Group, Hit, Outcome, Route, searchFn, SearchResult

### Community 87 - "sandbox.vnc.tsx"
Cohesion: 0.33
Nodes (4): ConnectionState, fetchVncStatus, Route, VncStatus

### Community 88 - "frontend-next"
Cohesion: 0.29
Nodes (6): Build and run, frontend-next, Local development, New-page review checklist (capped-truth discipline, #2179), Scaling (#1616), Verification

### Community 89 - "ConfirmDialog.tsx"
Cohesion: 0.38
Nodes (5): ConfirmHost(), ConfirmOptions, flash(), FlashHost(), FlashMessage

### Community 90 - "EsHistoryConsole.tsx"
Cohesion: 0.38
Nodes (6): bytesHuman(), ConsolePage, ConsoleRow, EsHistoryConsole(), EsStorage, fetchConsoleHistory

### Community 92 - "router.tsx"
Cohesion: 0.33
Nodes (5): getRouter(), Register, @tanstack/react-router, Register, routeTree

### Community 93 - "vite.config.ts"
Cohesion: 0.40
Nodes (4): @tailwindcss/vite, vite, @vitejs/plugin-react, config

### Community 97 - "logout.test.ts"
Cohesion: 0.40
Nodes (3): destroySession, getSession, handlers

### Community 100 - "sensors.index.tsx"
Cohesion: 0.67
Nodes (3): fetchCatalog, Route, SensorSummary

## Knowledge Gaps
- **741 isolated node(s):** `$schema`, `style`, `rsc`, `tsx`, `css` (+736 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 865 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `react` connect `react` to `canarytokens.tsx`, `reports.tsx`, `settings.tsx`, `index.tsx`, `formatTimestamp`, `payload-workbench.results.tsx`, `@tanstack/react-router`, `events.tsx`, `ips.tsx`, `ghidra.$sha.tsx`, `package.json`, `ErrorState.tsx`, `ml-anomalies.tsx`, `tty-replay.$shasum.tsx`, `sidebar.tsx`, `payload-analysis.$hash.tsx`, `prefs.ts`, `alerts.tsx`, `cn`, `sandbox.$job.tsx`, `EChart.tsx`, `AppShell.tsx`, `sensors.$sensor.tsx`, `topology.tsx`, `recent.ts`, `LiveToasts.tsx`, `Topbar.tsx`, `lib/live.ts`, `payloads.tsx`, `@tanstack/react-start`, `__root.tsx`, `reauth.ts`, `CuratedSensorViews.tsx`, `github-analysis.$sha.tsx`, `sessions.$id.tsx`, `sheet.tsx`, `CapturedMail.tsx`, `cape.$sha.tsx`, `credentials.tsx`, `button.tsx`, `source-health.tsx`, `revdeck.$sha.tsx`, `GhidraCallGraph.tsx`, `RowActions.tsx`, `search.tsx`, `sandbox.vnc.tsx`, `ConfirmDialog.tsx`, `EsHistoryConsole.tsx`, `-alerts.test.tsx`, `utils.ts`, `prefs.test.ts`?**
  _High betweenness centrality (0.137) - this node is a cross-community bridge._
- **Why does `@tanstack/react-router` connect `@tanstack/react-router` to `routeTree.gen.ts`, `canarytokens.tsx`, `reports.tsx`, `settings.tsx`, `index.tsx`, `formatTimestamp`, `getSession`, `payload-workbench.results.tsx`, `events.tsx`, `ips.tsx`, `ghidra.$sha.tsx`, `react`, `package.json`, `ErrorState.tsx`, `oidc.server.ts`, `vitest`, `ml-anomalies.tsx`, `tty-replay.$shasum.tsx`, `payload-analysis.$hash.tsx`, `alerts.tsx`, `cn`, `sensorProtocols.ts`, `sandbox.$job.tsx`, `AppShell.tsx`, `sensors.$sensor.tsx`, `proxyToRust`, `topology.tsx`, `LiveToasts.tsx`, `Topbar.tsx`, `payloads.tsx`, `@tanstack/react-start`, `__root.tsx`, `login.ts`, `github-analysis.$sha.tsx`, `sessions.$id.tsx`, `cape.$sha.tsx`, `credentials.tsx`, `source-health.tsx`, `revdeck.$sha.tsx`, `search.tsx`, `sandbox.vnc.tsx`, `router.tsx`, `sensors.index.tsx`?**
  _High betweenness centrality (0.077) - this node is a cross-community bridge._
- **Why does `@tanstack/react-start` connect `@tanstack/react-start` to `canarytokens.tsx`, `reports.tsx`, `settings.tsx`, `index.tsx`, `formatTimestamp`, `payload-workbench.results.tsx`, `@tanstack/react-router`, `auth.ts`, `events.tsx`, `ips.tsx`, `ghidra.$sha.tsx`, `react`, `package.json`, `ErrorState.tsx`, `ml-anomalies.tsx`, `tty-replay.$shasum.tsx`, `payload-analysis.$hash.tsx`, `prefs.ts`, `alerts.tsx`, `start.ts`, `sandbox.$job.tsx`, `AppShell.tsx`, `sensors.$sensor.tsx`, `topology.tsx`, `LiveToasts.tsx`, `Topbar.tsx`, `payloads.tsx`, `__root.tsx`, `CuratedSensorViews.tsx`, `github-analysis.$sha.tsx`, `sessions.$id.tsx`, `CapturedMail.tsx`, `cape.$sha.tsx`, `credentials.tsx`, `source-health.tsx`, `revdeck.$sha.tsx`, `GhidraCallGraph.tsx`, `search.tsx`, `sandbox.vnc.tsx`, `EsHistoryConsole.tsx`, `sensors.index.tsx`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **What connects `$schema`, `style`, `rsc` to the rest of the system?**
  _741 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `routeTree.gen.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.024510668312466937 - nodes in this community are weakly interconnected._
- **Should `canarytokens.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.07985480943738657 - nodes in this community are weakly interconnected._
- **Should `reports.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.05701754385964912 - nodes in this community are weakly interconnected._