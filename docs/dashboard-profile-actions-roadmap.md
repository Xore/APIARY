# Dashboard Profile Actions Roadmap

## Goal

Turn the authenticated identity at the bottom-left of the dashboard sidebar
into a keyboard-accessible floating action menu. Every authenticated user gets
**Settings** and **Logout**. Administrators additionally get **Admin settings**.
Settings remain owned and rendered by `Xore/auth-backend`; the dashboard only
navigates to the appropriate auth application pane.

The profile must display only the identity returned by auth-backend through
`GET /api/whoami`. Remove the `dashboard operator` placeholder and do not
invent a fallback username.

## Pinned references

- `Xore/theme` commit
  `efcc979faaa7d2dc9b533dfb0bfe8891ca3a9356`
  - `examples/components.html`, section **Floating layers**
  - `docs/MODALS.md`
  - `docs/ADOPTION.md`
- `Xore/auth-backend` commit
  `125c8371feaa7ddf99623744356c8d57281d6149`
  - `forward-auth/ui/app.html`
  - account pane: `/auth/app?pane=account`
  - administrator pane: `/auth/app?pane=admin-settings`

Re-pin and review these commits before implementation if either upstream
repository changes.

## Interaction and ownership

1. The sidebar profile is initially hidden and non-interactive.
2. `hp-app.js` requests `/api/whoami` with `cache: "no-store"`.
3. A successful response with a non-empty backend username/display name fills
   the name, avatar, role, capabilities, and server-approved action URLs, then
   reveals the profile trigger.
4. Clicking the trigger opens a floating menu above and to the right of the
   bottom-left anchor. Clicking again, clicking outside, pressing Escape, or
   navigating closes it.
5. **Settings** performs a top-level same-window navigation to auth-backend's
   account pane. Auth-backend opens and owns its permanent settings modal.
6. **Admin settings** is present only when the authenticated response grants
   administrator capability. It navigates to auth-backend's
   `admin-settings` pane.
7. **Logout** performs a top-level same-window navigation to the configured
   auth-backend logout endpoint.

Do not iframe, copy, proxy, or recreate auth-backend's settings UI. Same-window
navigation preserves auth-backend's cookie, routing, focus management,
authorization checks, and permanent-modal behavior.

## UI contract

Reuse the theme example's `.dropdown`, `.dropdown__item`, and
`.dropdown__divider` classes. Add only dashboard-specific anchoring rules.
Render the menu in a shell-level floating container with fixed positioning so
sidebar scrolling and collapsed-rail overflow cannot clip it. Calculate its
position from the trigger bounds and clamp it to the viewport on open, resize,
and scroll.

The profile row becomes a real `<button type="button">` with
`aria-haspopup="menu"`, `aria-expanded`, and `aria-controls`. The floating
layer uses `role="menu"` and its actions use `role="menuitem"`.

Keyboard behavior:

- Enter, Space, ArrowUp, or ArrowDown opens the menu and focuses an item.
- ArrowUp/ArrowDown, Home, and End move between enabled items.
- Escape closes the menu and restores focus to the profile trigger.
- Tab closes the menu and continues normal document focus order.
- Only one dashboard floating menu may be open at a time.

When the sidebar is collapsed, the trigger remains available through the
avatar and has an accessible label derived from the backend-provided identity.
The menu must remain usable at desktop, tablet, and mobile widths.

## Identity and security contract

Extend `/api/whoami` to return action URLs in addition to its existing stable
subject, username, display name, role, and capabilities. URLs must come from
explicit server configuration and be validated as allowed auth-backend HTTPS
targets; do not construct security-sensitive URLs from browser input.

Suggested configuration:

- `AUTH_ACCOUNT_URL=https://auth.example/auth/app?pane=account`
- `AUTH_ADMIN_SETTINGS_URL=https://auth.example/auth/app?pane=admin-settings`
- `AUTH_LOGOUT_URL=https://auth.example/_auth/logout`

The account and logout URLs are returned for every authenticated identity. The
admin URL is returned only when the live introspection result grants the
administrator capability. Menu visibility is convenience, not authorization:
auth-backend must re-check the session and role on every destination.

If `/api/whoami` fails, is unauthenticated, or lacks a non-empty backend
identity, keep the profile trigger and all actions hidden. Never show
`dashboard operator`, an email guessed from headers, a username hash, or any
other compatibility identity. Caller-provided `X-Auth-*` headers remain
non-authoritative.

## Delivery plan

### Milestone 1 — Backend action contract

1. Add and validate admin-settings and logout configuration beside the existing
   account URL.
2. Extend the typed `/api/whoami` response with action links, omitting the
   administrator link for non-admin users.
3. Add tests for user/admin responses, absent configuration, unsafe URL
   rejection, introspection failure, and forged-header denial.
4. Document variables in `.env.example` and wire them through Compose.

**Exit:** one authenticated response contains only the links that identity may
see, and failure remains closed.

### Milestone 2 — Profile trigger and floating layer

1. Remove the hard-coded `dashboard operator` text from
   `dashboard/ui/partials/dashboard.html`.
2. Add the semantic trigger and theme-compatible dropdown markup, initially
   hidden and inert.
3. Add minimal positioning/state styles through the dashboard Tailwind source;
   rebuild generated CSS using the documented frontend workflow.
4. Preserve the existing sidebar collapsed state and responsive layout.

**Exit:** no fallback identity appears in initial HTML and the closed layer has
no focusable descendants.

### Milestone 3 — Client behavior

1. Refactor the current `/api/whoami` initializer to reveal the profile only
   after a valid backend identity arrives.
2. Populate links from the response without synthesizing auth URLs in
   JavaScript.
3. Implement open/close, focus movement, outside-click dismissal, viewport
   positioning, and focus restoration in `dashboard/static/hp-app.js`.
4. Use `location.assign()` for settings and logout so navigation occurs in the
   top-level window.

**Exit:** users reach the account settings modal, administrators additionally
reach admin settings, and logout reaches auth-backend.

### Milestone 4 — Verification and rollout

Add Go/template and browser tests covering:

- initial HTML contains no `dashboard operator`;
- backend display name/username is the only rendered name;
- user versus administrator menu contents;
- account, admin-settings, and logout destination routing;
- direct access still denied by auth-backend for a non-admin;
- missing/failed identity leaves no misleading profile or enabled action;
- mouse, keyboard, Escape, outside click, focus restore, and single-menu rules;
- expanded/collapsed sidebar plus desktop/tablet/mobile viewport placement;
- generated CSS is current and CSP requires no inline handlers.

Deploy auth-backend route support/configuration first, then dashboard
configuration and UI. Smoke-test one normal account, one administrator, one
logout, and one revoked/expired session. Roll back the dashboard independently;
the auth-backend settings routes remain valid.

## Definition of done

- The bottom-left identity is exclusively auth-backend-provided.
- The profile trigger opens a theme-compatible floating action layer.
- Settings opens auth-backend's account settings modal.
- Administrators also receive the auth-backend admin-settings action.
- Logout ends the auth-backend session through its configured endpoint.
- Authorization, accessibility, responsive, and failure-mode tests pass.
- Configuration and deployment documentation match the shipped contract.
