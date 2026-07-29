package main

import (
	"bytes"
	"testing"
)

func TestModalRootDoesNotParticipateInAppShellGrid(t *testing.T) {
	css, err := staticAssets.ReadFile("static/hp-tailwind.css")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(css, []byte("#hp-modal-root{display:contents}")) {
		t.Fatal("compiled dashboard CSS must keep the modal host out of the app-shell grid")
	}
	if !bytes.Contains(css, []byte(".app-sidebar{grid-area:2/1}")) ||
		!bytes.Contains(css, []byte(".app-main{grid-area:2/2}")) {
		t.Fatal("compiled dashboard CSS must explicitly place sidebar and main content")
	}
}
