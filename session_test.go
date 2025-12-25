package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestNamespacesFromAccess(t *testing.T) {
	access := []Access{
		{Namespace: "team1"},
		{Namespace: "team2"},
		{Namespace: "team1"},
	}
	got := namespacesFromAccess(access)
	if len(got) != 2 || got[0] != "team1" || got[1] != "team2" {
		t.Fatalf("unexpected namespaces: %#v", got)
	}
}

func TestCreateSessionStoresData(t *testing.T) {
	resetSessions(t)
	user := &User{Name: "alice"}
	access := []Access{
		{Namespace: "team1"},
		{Namespace: "team2"},
		{Namespace: "team1"},
	}

	ctx, err := sessionManager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	start := time.Now()
	if err := createSession(ctx, user, access); err != nil {
		t.Fatalf("create session: %v", err)
	}
	token, _, err := sessionManager.Commit(ctx)
	if err != nil {
		t.Fatalf("commit session: %v", err)
	}
	end := time.Now()

	if token == "" {
		t.Fatalf("expected token to be set")
	}

	loadedCtx, err := sessionManager.Load(context.Background(), token)
	if err != nil {
		t.Fatalf("load committed session: %v", err)
	}
	sess, ok := sessionManager.Get(loadedCtx, sessionKey).(sessionData)
	if !ok {
		t.Fatalf("expected session to be stored")
	}
	if sess.User == nil || sess.User.Name != "alice" {
		t.Fatalf("unexpected user: %#v", sess.User)
	}
	expectedNamespaces := []string{"team1", "team2"}
	if !reflect.DeepEqual(sess.Namespaces, expectedNamespaces) {
		t.Fatalf("unexpected namespaces: %#v", sess.Namespaces)
	}
	if sess.CreatedAt.Before(start) || sess.CreatedAt.After(end) {
		t.Fatalf("unexpected CreatedAt: %v", sess.CreatedAt)
	}
}

func TestGetSessionValid(t *testing.T) {
	resetSessions(t)
	ctx, err := sessionManager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	sessionManager.Put(ctx, sessionKey, sessionData{
		User:      &User{Name: "tester"},
		CreatedAt: time.Now(),
	})
	token, _, err := sessionManager.Commit(ctx)
	if err != nil {
		t.Fatalf("commit session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	reqCtx, err := sessionManager.Load(req.Context(), token)
	if err != nil {
		t.Fatalf("load request session: %v", err)
	}
	req = req.WithContext(reqCtx)
	if _, ok := getSession(req); !ok {
		t.Fatalf("expected session to be valid")
	}
}

func TestGetSessionExpired(t *testing.T) {
	resetSessions(t)
	sessionManager.Lifetime = 10 * time.Millisecond
	ctx, err := sessionManager.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	sessionManager.Put(ctx, sessionKey, sessionData{
		User:      &User{Name: "tester"},
		CreatedAt: time.Now(),
	})
	token, _, err := sessionManager.Commit(ctx)
	if err != nil {
		t.Fatalf("commit session: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	reqCtx, err := sessionManager.Load(req.Context(), token)
	if err != nil {
		t.Fatalf("load request session: %v", err)
	}
	req = req.WithContext(reqCtx)
	if _, ok := getSession(req); ok {
		t.Fatalf("expected session to be expired")
	}
}

func resetSessions(t *testing.T) {
	t.Helper()
	sessionManager = newSessionManager()
	t.Cleanup(func() {
		sessionManager = newSessionManager()
	})
}
