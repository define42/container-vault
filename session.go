package main

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

const sessionKey = "session"

var sessionManager = newSessionManager()

func init() {
	gob.Register(sessionData{})
}

func newSessionManager() *scs.SessionManager {
	manager := scs.New()
	manager.Store = memstore.New()
	manager.Lifetime = sessionTTL
	manager.Cookie.Name = "cv_session"
	manager.Cookie.Path = "/"
	manager.Cookie.HttpOnly = true
	manager.Cookie.SameSite = http.SameSiteLaxMode
	manager.Cookie.Secure = true
	return manager
}

func createSession(ctx context.Context, u *User, access []Access) error {
	namespaces := namespacesFromAccess(access)
	if err := sessionManager.RenewToken(ctx); err != nil {
		return err
	}
	sessionManager.Put(ctx, sessionKey, sessionData{
		User:       u,
		Access:     access,
		Namespaces: namespaces,
		CreatedAt:  time.Now(),
	})
	return nil
}

func getSession(r *http.Request) (sessionData, bool) {
	sess, ok := sessionManager.Get(r.Context(), sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return sessionData{}, false
	}
	return sess, true
}

func destroySession(ctx context.Context) error {
	return sessionManager.Destroy(ctx)
}

func namespacesFromAccess(access []Access) []string {
	seen := make(map[string]struct{})
	var namespaces []string
	for _, a := range access {
		if _, ok := seen[a.Namespace]; ok {
			continue
		}
		seen[a.Namespace] = struct{}{}
		namespaces = append(namespaces, a.Namespace)
	}
	return namespaces
}
