package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestModalRootDoesNotParticipateInAppShellGrid(t *testing.T) {
	css, err := staticAssets.ReadFile("static/hp-dashboard.css")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(css, []byte("#hp-modal-root { display: contents; }")) {
		t.Fatal("dashboard CSS must keep the modal host out of the app-shell grid")
	}
	if !bytes.Contains(css, []byte(".app-sidebar { grid-column: 1; grid-row: 2; }")) ||
		!bytes.Contains(css, []byte(".app-main { grid-column: 2; grid-row: 2; }")) {
		t.Fatal("dashboard CSS must explicitly place sidebar and main content")
	}
}

func TestAccountMenuAndSettingsPopup(t *testing.T) {
	partial := mustReadUI("partials/dashboard.html")
	for _, marker := range []string{
		`data-hp-account-trigger`,
		`data-hp-account-menu`,
		`data-hp-account-settings`,
		`data-hp-account-logout`,
		`id="hp-settings-dialog"`,
		`data-hp-settings-frame`,
		`/static/hp-account.js`,
	} {
		if !strings.Contains(partial, marker) {
			t.Fatalf("dashboard shell missing account-menu marker %q", marker)
		}
	}
	if strings.Contains(partial, "dashboard operator") {
		t.Fatal("sidebar profile must render only the auth-backend provided name, not a fabricated placeholder")
	}
	if _, err := staticAssets.ReadFile("static/hp-account.js"); err != nil {
		t.Fatal("static/hp-account.js must be embedded with the dashboard assets")
	}
	css, err := staticAssets.ReadFile("static/hp-dashboard.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"button.sidebar__profile", ".hp-account-menu", ".hp-settings-frame"} {
		if !bytes.Contains(css, []byte(marker)) {
			t.Fatalf("dashboard CSS missing %s", marker)
		}
	}
}
