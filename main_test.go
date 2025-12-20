package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCvRouterRootRedirectsToLogin(t *testing.T) {
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestCvRouterLoginGet(t *testing.T) {
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Fatalf("expected login form in response")
	}
}

func TestCvRouterApiRequiresSession(t *testing.T) {
	resetSessions(t)
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestCvRouterStaticSetsNoCache(t *testing.T) {
	staticDir := "static"
	_, err := os.Stat(staticDir)
	dirExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat static dir: %v", err)
	}
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("mkdir static dir: %v", err)
	}
	staticFile := filepath.Join(staticDir, "test.css")
	if err := os.WriteFile(staticFile, []byte("body{}"), 0o644); err != nil {
		t.Fatalf("write static file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(staticFile)
		if !dirExisted {
			_ = os.Remove(staticDir)
		}
	})

	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/test.css", nil)

	router.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("expected Cache-Control header to be set, got headers: %#v", rec.Header())
	}
}
