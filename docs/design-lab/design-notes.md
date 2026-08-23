# APIARY dashboard design review — dashboard.example — 2026-08-17
## Findings (running)
- Overview (light): loads fast, authenticated. Heatmap "Activity — last 24h" dominates; lower rows (multipot, conpot-kamstrup, endlessh) appear near-empty/pale — visual weight wasted?
- Theme toggle: monitor icon top-right (left of LIVE). Dark theme renders correctly on Overview.
- Overview heatmap card ("Activity — last 24h") is a fixed-height inner scroll container: mouse wheel over it scrolls the card, not the page (scroll trap); inner scrollbar is very subtle. ~13+ sensor rows hidden below the fold of the card.
- Heatmap uses one global color scale: dionaea (~90k/h) saturates; low-volume sensors (multipot ~240/h, endlessh, galah) render near-empty. Per-sensor normalization would make rows readable.
- Header alert badge shows "99+" — alert count overflow, arguably alarming-by-default.
- Overview "Recent events": every row renders its FULL normalized-event JSON article inline (#1447 intentional). On Overview this makes the stream ~18 x ~600px of JSON inside a fixed-height card__scroll; the table header (time/sensor/source ip/port/detail) no longer matches what the eye sees. Suggest: compact rows on Overview stream (detail on /events only), or max-height+inner-scroll on the article, or collapse-with-summary that keeps content in DOM for a11y.
- Events table: "source ip" column too narrow → IP wraps mid-address (203.0.113.1 / 22); country badge wraps below. Port cell renders ":25" with leading colon — stylistic, looks like a typo when cell wraps.
- Heatmap card keeps internal scroll position after page scroll; no affordance that rows are hidden above/below inside the card.
- Sections on Live operations tab: Current activity (heatmap), Attack origins — live geographic view (map), Collection status (Sensor feeds, Protocols probed), ML classification backlog, Live event stream.
- "Attack origins" Leaflet map (dark): world tiles don't fill card width at zoom 2 — large blank light-gray gutters left/right clash with dark theme; "World" reset control top-right is clipped mid-word; Leaflet attribution overlaps the card's bottom edge. Suggest maxBounds/fitBounds or ocean-colored background + unclipped control.
- Uniform 340px card__scroll heights force inner scrolling on nearly every Overview card (heatmap 1357px, sensor feeds 1073px, recent events 11018px inside 340px!). Consider taller defaults or per-card sizing.
- Sensor feeds: count column (accent-colored links) sits far from sensor badge; ACTIVE status + relative time right-aligned — scannable but the wide empty middle reads as a layout gap at 1568px.
## Threat landscape tab
- 127.0.0.1 ranks #6 in "Top source IPs" (94k events) — loopback/tunnel artifact polluting top-N; filter or label it.
- "Network/provider classes" card: 4 short rows in a full-height card next to a packed 340px-scroll "Top autonomous systems" — unbalanced pair.
- Traffic volume bytes + packets: two stacked near-identical spiky linear charts; raw axis numbers ("25,000,000,000") — humanize units (GB, M pkts), consider log scale or merged dual-axis card.
- "Protocol-conformance violations": empty state renders "No data yet." twice (chart center + caption below).
- "Top exploited CVEs": with 2 buckets, first bar is a giant unstyled gray slab ~40% of card width; second bar invisible (zero height rendering); rotated x-labels truncated ("DoublePulsar connection at…"). Needs barMaxWidth, readable labels, non-fallback color.
## Attacker behavior tab (pre-refresh snapshot)
- "Top commands" list shows visually duplicate entries: "enable" x2, "linuxshell" x2, "shell" x2, each 623 — likely trailing-whitespace/variant strings rendered identically; dedupe or make the difference visible.
- Attacker OS donut: callout labels for tiny slices pile up/overlap at the top (7 labels stacked, leader lines crossing); legend below already covers them — drop callouts for <2% slices.
- "TLS scanner fingerprints (JA4)" bar chart: 15 rotated x-labels are long truncated hashes ("t13i1910q0_9dc949149365…") — unreadable; bars all same gray. Horizontal bars + copyable full hash tooltip would serve better.
- (paused here: user is redeploying a layout change; Evidence & campaigns tab + light-theme pass still pending)
## Post-refresh session
- BUG (repro'd): clicking the theme toggle shortly after first page load does not persist — hp-app.js savePrefs() early-returns while prefState.ready=false, so only localStorage is set; the subsequent server prefs sync ("system") then overwrites it on next load. Once prefs are ready the toggle persists fine (verified r14->r15). Fix: queue the pending patch until ready, or apply localStorage as source-of-truth when server still has defaults.
- Theme cycle is system -> dark -> light with no visible state indication beyond a title tooltip; 3-state cycle on an icon button is hard to discover (user had to tell me where it is). Consider a small menu or showing the active mode.
## Evidence & campaigns tab
- "Suricata alerts" empty state leaks an ops diagnostic ("no alerts — is the VPS eve.json mount at /logs/suricata alive?") while sensor feeds show suricata ACTIVE with 1.4M events — either a data-path regression or wrong empty-state copy; sibling card says "no suricata alerts yet" (inconsistent phrasing).
- "Correlated campaigns": score column shows 100 for every row (capped) — a column of identical values carries no information; consider hiding or showing the raw components. Header link copy "Every column, every network →" is cryptic.
## ML anomalies page (dark)
- Top bar center label reads "Operations" on this page (and page category is DETECTION) — topbar/page title mapping inconsistent (Overview page correctly says "Overview").
- KPI tile "0 Anomalies, 24h" directly above a long table of OPEN anomalies from 6 days ago — leading stat contradicts what the eye sees; show open-backlog count alongside.
- Table: explanation column repeats "Statistical outlier (composite score X)" on every row (redundant with score column); timestamps are raw ISO-with-millis ("2026-08-11T12:35:43.666Z") unlike the rest of the app; ~40 identical "acknowledge" buttons with no bulk action; several exact-duplicate rows (same second, same IP) differing only by 0.01 score.
- Chart legend: "lstm_ae" series color is a dim gray-blue, label+points nearly invisible in dark theme.
- Filter popover: fine (native selects), no explicit close affordance.
## LLM analysis / Agent campaigns / Auth-failure events (dark)
- Topbar center label says "Operations" on all Monitor pages regardless of the page (title mapping bug/inconsistency).
- Auth-failure events: the ONLY content is a table, yet it's confined to a ~300px card__scroll with a clipped half-row at its edge while the rest of the viewport is blank — single-table pages should let the table grow. Timestamps are raw "2026-08-11T15:23:03.350000+00:00" (microseconds+offset). "0 Failed logins, 24h" tile above a card full of older rows (same pattern as ML anomalies).
- LLM analysis: pre-search the semantic-search card shows an empty results table with headers + placeholder row — could hide the table until a query runs.
- Empty states are inconsistent across pages: "No LLM analysis documents yet." / "No campaign has crossed a criticality-rule threshold yet." / "no suricata alerts yet" / "No data yet." — different tones and capitalization.
## SPA-feel (user goal)
- Requirement from Xore: the dashboard should feel like ONE page — persistent shell, only center content swaps; never a full browser reload. Today only the #1139/#1141 payload/results family uses fetch-and-swap (hp-dynamic-nav.js DYNAMIC_ROUTES + hp-app.js mountPage/replaceHoneypotPage); every sidebar link is a full navigation. Proposal: generalize the existing mechanism to all shell routes (sidebar, topbar links, back/forward via pushState), with per-page script re-init handled the way hp-dynamic-nav already does for its family.
## CRITICAL: session decay silently kills all JS features
- Repro: leave any page open ~5-10 min. Every /api/* fetch starts returning 401 "authentication required" (filter-values, settings/me, stats, whoami). Full-page navigation still works (redirect re-auth), so the operator sees a live-looking page whose filters return nothing, theme/preference saves are dropped (explains #1561's visible symptom), SSE stream dead. After manual reload, everything works again (filter-values returns 20 sensors).
- Fix directions: on first 401 from any fetch, transparently re-auth (hidden iframe/redirect w/ prompt=none) or show a "session expired — click to renew" toast; make refreshSession actually keep API sessions alive under an open page (the 1-min proactive window may be misconfigured vs Keycloak token lifetimes).
## Events filter popover
- Autocomplete (#303) works when session is fresh: click sensor field → real values+counts. Missing on "attack path" and "since" fields (no data-hp-filter-field). Popover styling consistent.
## User directives collected during review
- One flawless page: SPA-feel, only center content refreshes (generalize hp-dynamic-nav to all routes).
- Pages must fill viewport height/width with modest padding; Event explorer card called out as "very small, hard to see".
- Filter fields should auto-populate on click (works, but broken by session decay; add to attack-path/since too).
- Nav list should include hidden routes (found in routes.go, not in sidebar): /alerts, /source-health, /search, /sensors, /history, /dead-letters, /canarytokens, /ghidra, /revdeck, /cape, /github-analysis, /sandbox, /payload-workbench, /problem-reports(?), settings modal. Decide which become nav entries (grouped), which stay contextual.
- Build local variant dashboard w/ real data (homeserver xore@<homeserver>) for side-by-side design choices incl. PDF design.
## Investigate pages (rest)
- /ips: solid table; date cols wrap to 2 lines at 1568px; source-ip wraps mid-IP occasionally.
- /campaigns: worst column-crush — network CIDR wraps mid-value ("169.58.1/70.0/24"), provider wraps "networ/k", dates wrap "2026-/08-16", trailing "ES →" col clipped by card edge; 15 columns is too many for one table. Card shows ~4.5 rows, half viewport dead below.
- /clusters: fine; "1 sensors:" grammar; investigate→/ES→ twin link columns could be one action menu.
- /attackers: long skeleton load (~10s+); first/last timestamps wrap mid-CHARACTER across 3 lines ("2026-08-1 / 6T23:17:0 / 1Z"); verdict badge only on some rows; entity ids as bare hex links.
- /kill-chain: sankey good; "Execution/Initial Access" node labels overlap; ATT&CK coverage grid uses LIGHT-GRAY zebra columns in dark theme (clashes hard); campaign timeline chart is nice.
- /commands: best data page — horizontal bars readable; sources column crams 5 IPs + "+15"; dates wrap "2026-/08-16".
- /recordings: clean; consistent.
## Reports studio
- Strongest page overall: numbered step tabs, template gallery, sticky action bar, PDF theme toggle pills. Template grid leaves a hole (9 cards in 6-wide grid).
- Library: generated-report card exposes Delete right next to Download (destructive adjacency, no confirm visible); saved-definitions empty-state fine.
## PDF (Payload Analysis Report, dark theme)
- Branded header + stat tiles look good; BUT tile values truncate mid-word with ellipsis ("Windows DLL / pe-d…", "6.380 (not packed-l…") — unacceptable in a print artifact; tiles need wrap/autosize.
- Copy bug: "Observed window: not available to not available".
- 3 pages; body typography consistent; consider light-theme default for print friendliness (dark PDF prints badly).
## Header/menus/dialogs
- Search overlay: no live suggestions while session decayed; pressing Enter did nothing (silently dead). With fresh session untested-live but code has preview.
- /alerts: 200 identical-class YARA alerts flood the list (source of the perpetual "99+" badge); per-row acknowledge + "acknowledge all (200)"; consider grouping by rule with counts.
- /source-health: good page (KPI row, two-column detail, inline footnote). ES health chip "ES yellow" plain-text — could be a status badge.
- Account menu (Dashboard settings / Account & security / Log out) fine; settings modal is well-structured (search, Personal/Administration groups, Appearance has theme/density/motion/high-contrast/large-text).
- BUG "Report a problem" dialog: form fields clipped at viewport top, title "Report a problem" renders detached mid-dialog BELOW the form, bottom half of modal empty — broken layout order/positioning.
- Sensor detail page exists in nav now (new deploy); session ids/timestamps wrap; card 340px again.
## claude.ai exhaustive audit (patterns catalog, 2026-08-17)
Pressed/inspected: sidebar collapse (+tooltip w/ Ctrl+B hint), sidebar search → centered overlay (first result preselected, "Enter" chip, relative ages right), Home/Code segmented toggle, + attach menu (grouped, submenu chevrons, shortcut hints, checkmark toggles), model selector (name + one-line description, Effort submenu, "More models" disclosure), incognito ghost icon (distinct darker full-screen mode w/ serif headline + explainer + chrome-less top bar), Recents page (serif title + right toolbar: search/filter/Select/primary), Artifacts (scope text-tabs All/Yours/Shared; illustrated empty state w/ headline+copy+CTA), Scheduled (empty state + dashed divider + TEMPLATE GALLERY: icon/title/desc/schedule chip), Customize → settings modal deep-link (Skills table w/ Browse+Add toolbar), settings modal (search-topped rail, label-left/control-right rows, 3-icon appearance segmented), chat-row hover kebab + section-label hover controls, humane 404 ("…finding this page isn't one of them" + Go back home). Skipped: logout, billing/payment/upgrade, mic/dictation, sending messages.
Adoption ideas for APIARY (follow-ups): template-gallery empty states (reports/canarytokens/scheduled-reports), witty 404 page, "Enter" hint chip in palette results, tooltip+shortcut hints on icon buttons, hover kebab on table rows (partially done via 14B), settings deep-links from sidebar.
