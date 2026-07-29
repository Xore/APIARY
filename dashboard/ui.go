package main

import (
	"embed"
	"fmt"
)

// uiFS is the render-engine migration target for file-based dashboard
// templates. Shared partials are embedded first; route templates will move
// here incrementally without changing their public routes or data contracts.
//
//go:embed ui
var uiFS embed.FS

func mustReadUI(name string) string {
	path := "ui/" + name
	data, err := uiFS.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read embedded dashboard UI %q: %v", path, err))
	}
	return string(data)
}
