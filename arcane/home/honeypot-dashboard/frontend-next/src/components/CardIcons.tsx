// Result-card icons, lifted verbatim from the pre-port Go templates'
// `.project-card__icon` SVGs (ui/{payload_workbench,payloads,sandbox,
// ghidra,github_analysis,reports}.html). theme.css sizes these at 16px
// via `.project-card__icon svg`; they carry no colour of their own so the
// card's own icon rule tints them.
//
// Two grids the Go dashboard never rendered as cards — static analysis and
// YARA — reuse the closest icon from this same set rather than introducing
// new artwork: a file for "this analysed one file", a shield for "these
// rules matched".

const ICON_PROPS = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const

/** payload_workbench.html — stacked panes, one per analyzer. */
export const WorkbenchIcon = (
  <svg {...ICON_PROPS}>
    <path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" />
  </svg>
)

/** payloads.html — a captured file. */
export const FileIcon = (
  <svg {...ICON_PROPS}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
  </svg>
)

/** sandbox.html — the detonation container. */
export const SandboxIcon = (
  <svg {...ICON_PROPS}>
    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
  </svg>
)

/** ghidra.html — decompilation. */
export const CodeIcon = (
  <svg {...ICON_PROPS}>
    <polyline points="16 18 22 12 16 6" />
    <polyline points="8 6 2 12 8 18" />
  </svg>
)

/** github_analysis.html — multi-engine verdict. */
export const ShieldIcon = (
  <svg {...ICON_PROPS}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
)

/** reports.html — a generated report. */
export const ReportIcon = (
  <svg {...ICON_PROPS}>
    <path d="M4 19V9M10 19V5M16 19v-7M22 19V3" />
  </svg>
)
