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
}
