package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func authenticate(w http.ResponseWriter, r *http.Request) (*User, bool) {
	fmt.Println(r.Header)
	username, password, ok := r.BasicAuth()
	fmt.Println("sssssssssssssssss:", username)
	if !ok || password == "" {
		fmt.Println("write header WWW-Authenticate")
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return nil, false
	}

	u, err := ldapAuthenticate(username, password)
	if err != nil {
		log.Printf("ldap auth failed for %s: %v", username, err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil, false
	}

	return u, true
}

func authorize(u *User, r *http.Request) bool {
	// Allow registry ping after authentication
	if r.URL.Path == "/v2/" {
		return true
	}

	// Path must be /v2/<namespace>/...
	prefix := "/v2/" + u.Namespace + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}

	// Pull-only enforcement
	if u.PullOnly {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return true
		default:
			return false
		}
	}

	if r.Method == http.MethodDelete {
		return u.DeleteAllowed
	}

	return true
}
