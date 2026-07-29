# Dashboard Profile Actions Roadmap

## Goal

Turn the authenticated identity at the bottom-left of the dashboard sidebar
into a keyboard-accessible floating action menu. Every authenticated user gets
**Settings** and **Logout**. Administrators additionally get **Admin settings**.

Clicking a settings action opens a centered modal over the dashboard. Reuse
the `Xore/auth-backend` settings UI and controller where practical, or
faithfully replicate the pinned implementation when direct reuse is not
possible. Auth-backend remains authoritative for identity, settings data,
validation, authorization, and writes.

The profile displays only identity returned by auth-backend through
`GET /api/whoami`. Remove `dashboard operator` and never invent a fallback.

## Pinned references

- `Xore/theme` commit
  `efcc979faaa7d2dc9b533dfb0bfe8891ca3a9356`
  - `examples/components.html`, section **Floating layers**
  - `docs/MODALS.md`
  - `docs/ADOPTION.md`
- `Xore/auth-backend` commit
  `125c8371feaa7ddf99623744356c8d57281d6149`
  - `forward-auth/ui/app.html`
  - account pane: `account`
  - administrator pane: `admin-settings`

Re-pin and review these commits before implementation if either upstream
repository changes.

## Interaction

1. The sidebar profile is initially hidden and non-interactive.
2. `hp-app.js` requests `/api/whoami` with `cache: "no-store"`.
3. A valid response fills the backend name, avatar, role, capabilities, and
   server-approved integration data, then reveals the profile trigger.
4. Clicking the profile opens a floating menu above and to the right. Clicking
   again, clicking outside, or pressing Escape closes it.
5. **Settings** closes the menu and opens the account pane in a centered popup
   over the dashboard.
6. **Admin settings** appears only for an authenticated administrator and opens
   the same popup directly on `admin-settings`, including admin navigation.
7. **Logout** performs a top-level same-window navigation to auth-backend's
   configured logout endpoint.

Pane switching stays inside the popup and must not navigate away from or reload
the dashboard.

## Reuse strategy

Preferred: extract the auth-backend settings shell, pane definitions, client
controller, and theme-dependent styles into versioned reusable assets consumed
by auth-backend and the dashboard.

Fallback: copy the pinned auth-backend modal structure, theme classes, and
behavior into a dedicated dashboard module. Record the upstream commit beside
the copy, document intentional differences, and add a parity test so upstream
drift is visible. Do not duplicate authentication, authorization, validation,
or persistence logic.

An iframe is not the default because it complicates CSP `frame-ancestors`,
cross-origin focus, sizing, and message authentication. It is acceptable only
if auth-backend adds an explicit embedded mode with:

- a narrow origin allowlist and explicit CSP;
- an authenticated, origin-checked `postMessage` contract;
- embedded sizing and close events;
- correct session-expiry, logout, focus, and WebAuthn behavior;
- browser tests for normal and administrator accounts.

A raw full-page iframe is not an implementation.

## UI contract

### Profile floating layer

Reuse the theme example's `.dropdown`, `.dropdown__item`, and
`.dropdown__divider` classes. Add only dashboard-specific anchoring rules.
Render the menu in a shell-level fixed container so sidebar scrolling and
collapsed-rail overflow cannot clip it. Position from the trigger bounds and
clamp to the viewport on open, resize, and scroll.

The profile row becomes `<button type="button">` with `aria-haspopup="menu"`,
`aria-expanded`, and `aria-controls`. The layer uses `role="menu"` and its
actions use `role="menuitem"`.

- Enter, Space, ArrowUp, or ArrowDown opens and focuses the menu.
- ArrowUp/ArrowDown, Home, and End move between enabled items.
- Escape closes and restores focus to the profile trigger.
- Tab closes and continues normal focus order.
- Only one dashboard floating menu may be open.
- A collapsed sidebar retains an accessible label derived from the backend
  identity.

### Centered settings modal

Reuse auth-backend's `.modal`, `.modal__sidebar`, `.modal__content`,
settings-navigation, pane, form, badge, button, and nested-dialog contracts.
Unlike auth-backend's current permanent full-viewport app, present this
instance as a dismissible popup centered over the dashboard:

- fixed dimmed backdrop covering the dashboard;
- dialog approximately `min(1100px, calc(100vw - 32px))` by
  `min(760px, calc(100dvh - 32px))`;
- theme surface, border, radius, and modal shadow tokens;
- auth-backend sidebar/content layout on wide screens and its responsive
  pattern on narrow screens;
- visible close button in the modal header;
- opening focuses the selected pane, traps focus, and marks the dashboard
  shell inert;
- Escape closes the deepest nested confirmation first, then the settings
  modal; closing restores focus to the profile trigger;
- backdrop click closes only when no write, WebAuthn ceremony, or confirmation
  is pending;
- auth-backend visual language for loading, success, validation,
  authorization, expired-session, and retry states.

The initial pane is `account` for **Settings** and `admin-settings` for
**Admin settings**. Normal users never receive or render administrator
navigation.

## Backend and security contract

Extend `/api/whoami` with settings capabilities and a server-approved
integration endpoint. Configuration must be validated as an allowed
auth-backend HTTPS target; never construct security-sensitive URLs from
browser input.

Suggested configuration:

- `AUTH_SETTINGS_API_URL=https://auth.example/_auth/settings/api`
- `AUTH_LOGOUT_URL=https://auth.example/_auth/logout`

Add a documented auth-backend settings API or embeddable-controller contract
for account data, passkeys, sessions, preferences, and admin settings. Prefer
same-origin routing through the authenticated edge. If a dashboard server
proxy is required, make it a narrow allowlisted pass-through that:

- preserves method and status semantics;
- forwards only the authenticated session and required CSRF data;
- applies request, response-body, and timeout limits;
- never logs credentials, CSRF tokens, passkey data, or secrets;
- does not introduce permissive CORS.

The settings capability and logout URL are returned for every authenticated
identity. Admin panes/actions are enabled only when live introspection grants
administrator capability. Visibility is not authorization: auth-backend
re-checks session, CSRF token, role, and payload for every read and write.

If `/api/whoami` fails or lacks a non-empty backend identity, keep the profile
and actions hidden. Never show `dashboard operator`, a guessed header value,
username hash, or compatibility identity. Caller-provided `X-Auth-*` headers
remain non-authoritative.

## Delivery plan

### Milestone 1 — Integration contract

1. Define the reusable settings controller/API contract with auth-backend,
   including CSRF, session expiry, WebAuthn, and administrator authorization.
2. Add and validate settings and logout configuration.
3. Extend `/api/whoami` with settings capabilities, omitting administrator
   capability for non-admin users.
4. Test user/admin responses, missing configuration, unsafe URL rejection,
   introspection failure, and forged-header denial.
5. Document variables in `.env.example` and Compose.

**Exit:** an authenticated response exposes only appropriate capabilities and
failures remain closed.

### Milestone 2 — Profile floating layer

1. Remove `dashboard operator` from
   `dashboard/ui/partials/dashboard.html`.
2. Add the semantic profile trigger and theme dropdown, initially hidden and
   inert.
3. Add minimal positioning/state styles and rebuild generated CSS.
4. Preserve expanded, collapsed, and responsive sidebar layouts.

**Exit:** initial HTML has no fallback identity and the closed menu has no
focusable descendants.

### Milestone 3 — Reusable centered settings modal

1. Extract and version auth-backend's settings shell, navigation, controller,
   and styles for reuse by both applications.
2. If extraction is blocked, replicate the pinned DOM/classes and behavior in
   a dedicated dashboard module with an upstream-parity test.
3. Adapt the permanent full-screen modal into the centered, dismissible
   dashboard modal without changing field semantics.
4. Connect reads/writes to auth-backend through the approved integration
   endpoint; keep authorization and validation server-side.
5. Support account, passkeys, sessions, and admin settings with matching
   loading, confirmation, error, and success behavior.

**Exit:** the popup visually and behaviorally matches auth-backend and setting
changes persist through auth-backend.

### Milestone 4 — Client orchestration

1. Reveal the profile only after a valid backend identity arrives.
2. Populate capabilities and integration data from `/api/whoami` without
   synthesizing auth URLs in JavaScript.
3. Implement menu open/close, keyboard movement, outside-click dismissal,
   viewport positioning, and focus restoration in `hp-app.js`.
4. Open account/admin panes in the centered modal; use `location.assign()` only
   for top-level logout.

**Exit:** users edit account settings without leaving the dashboard,
administrators reach admin settings, and logout reaches auth-backend.

### Milestone 5 — Verification and rollout

Add Go/template and browser tests for:

- no `dashboard operator` in initial HTML;
- backend name as the only rendered identity;
- user versus administrator menu and modal navigation;
- account/admin initial pane selection and logout routing;
- visual parity with the pinned auth-backend modal;
- settings reads/writes, validation, CSRF rejection, server errors, and expired
  sessions;
- auth-backend denial of direct non-admin access;
- failed identity leaving no misleading profile or enabled action;
- mouse, keyboard, Escape, outside click, and focus restoration;
- modal focus trap, inert dashboard, nested confirmations, and safe dismissal;
- expanded/collapsed sidebar and desktop/tablet/mobile layouts;
- current generated CSS and no CSP-violating inline handlers.

Deploy reusable auth-backend assets/API and edge policy first, then dashboard
configuration and UI. Smoke-test a user setting write, a passkey/session
action, an administrator setting write, logout, and a revoked session.

## Definition of done

- The bottom-left identity is exclusively auth-backend-provided.
- The profile opens a theme-compatible floating action layer.
- Settings opens a centered, dismissible auth-backend-compatible popup over
  the dashboard without navigation.
- Administrators receive admin settings in the same popup.
- UI is reused from auth-backend or verifiably kept in parity.
- Auth-backend reads, validates, authorizes, and persists every setting.
- Logout ends the auth-backend session through its configured endpoint.
- Authorization, accessibility, responsive, parity, and failure tests pass.
