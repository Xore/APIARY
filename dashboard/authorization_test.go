package main

import (
	"net/http/httptest"
	"testing"
)

func TestRequireAdmin(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	denied := httptest.NewRecorder()
	if requireAdmin(denied, httptest.NewRequest("GET", "/payload/hash", nil)) {
		t.Fatal("request without a role was allowed")
	}
	if denied.Code != 403 {
		t.Fatalf("status = %d, want 403", denied.Code)
	}

	request := httptest.NewRequest("GET", "/payload/hash", nil)
	request.Header.Set("X-Auth-Role", "admin")
	if !requireAdmin(httptest.NewRecorder(), request) {
		t.Fatal("admin request was denied")
	}
}
