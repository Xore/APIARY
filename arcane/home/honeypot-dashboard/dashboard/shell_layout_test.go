package main

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
)

func TestStaticDashboardStylesLiveInVendoredTheme(t *testing.T) {
	err := fs.WalkDir(uiFS, "ui", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		body, err := uiFS.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(body, []byte("<style")) {
			return nil
		}
		if path != "ui/overview.html" || !bytes.Contains(body, []byte(`<style nonce="{{.Nonce}}">`)) {
			t.Errorf("%s contains static page CSS; dashboard styling belongs in vendored Xore/theme", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestModalRootDoesNotParticipateInAppShellGrid(t *testing.T) {
	css, err := staticAssets.ReadFile("static/theme.css")
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

func TestAccountMenuUsesTopLevelKeycloakAccount(t *testing.T) {
	partial := mustReadUI("partials/dashboard.html")
	for _, marker := range []string{
		`data-hp-account-trigger`,
		`data-hp-account-menu`,
		`data-hp-account-settings`,
		`data-hp-account-logout`,
		`/static/hp-account.js`,
	} {
		if !strings.Contains(partial, marker) {
			t.Fatalf("dashboard shell missing account-menu marker %q", marker)
		}
	}
	for _, forbidden := range []string{"dashboard operator", `data-hp-settings-frame`, `id="hp-settings-dialog"`} {
		if strings.Contains(partial, forbidden) {
			t.Fatalf("sidebar retains removed embedded-account marker %q", forbidden)
		}
	}
	if _, err := staticAssets.ReadFile("static/hp-account.js"); err != nil {
		t.Fatal("static/hp-account.js must be embedded with the dashboard assets")
	}
	css, err := staticAssets.ReadFile("static/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"button.sidebar__profile", ".hp-account-menu"} {
		if !bytes.Contains(css, []byte(marker)) {
			t.Fatalf("dashboard CSS missing %s", marker)
		}
	}
}
