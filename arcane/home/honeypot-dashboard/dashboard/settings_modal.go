package main

// settingsModal is the centered settings dialog rendered as a reusable
// fragment (roadmap §7): hp-settings.js fetches it once per session from
// /api/settings/modal, injects it into the dashboard shell's modal root, and
// drives it as an application-managed overlay per the theme modal contract
// (docs/MODALS.md in Xore/theme). The nested save/reset confirmation is a
// native dialog descendant of the modal, so the top-layer invariant holds.
//
// The administration panes (Milestone E) render only when the server resolved
// the caller as an admin — hiding is server-side, never client-side alone
// (§12): non-admins receive a document without any admin markup at all.
//
// settingsPageData carries the template inputs for the settings modal.
type settingsPageData struct {
	Admin bool
}

var settingsModal = mustReadUI("partials/settings_modal.html")

// Design refresh (pick 13B): /settings renders the same settings surface
// as a full page in the shell; hp-settings.js fetches the modal fragment
// into the page's host and strips the modal chrome client-side.
var pageSettingsPage = mustReadUI("settings_page.html")

// settingsPageView is the full-page wrapper's template input -- the shell
// needs a nonce; the subtitle needs the same admin resolution the modal
// fragment does.
type settingsPageView struct {
	pageMeta
	Admin bool
}
