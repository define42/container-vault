package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

var (
	sessionMu sync.Mutex
	sessions  = map[string]sessionData{}
)

func createSession(u *User, access []Access) string {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	namespaces := namespacesFromAccess(access)

	sessionMu.Lock()
	sessions[token] = sessionData{
		User:       u,
		Access:     access,
		Namespaces: namespaces,
		CreatedAt:  time.Now(),
	}
	sessionMu.Unlock()

	return token
}

func getSession(r *http.Request) (sessionData, bool) {
	cookie, err := r.Cookie("cv_session")
	if err != nil || cookie.Value == "" {
		return sessionData{}, false
	}

	sessionMu.Lock()
	defer sessionMu.Unlock()

	sess, ok := sessions[cookie.Value]
	if !ok {
		return sessionData{}, false
	}
	if time.Since(sess.CreatedAt) > sessionTTL {
		delete(sessions, cookie.Value)
		return sessionData{}, false
	}
	return sess, true
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
