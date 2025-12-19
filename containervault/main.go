package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

func main() {
	// Use single-host reverse proxy to forward traffic to the registry
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
	}

	proxy.FlushInterval = -1 // important for streaming blobs

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			serveLanding(w)
			return
		}

		if r.URL.Path == "/login" {
			handleLogin(w, r)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/dashboard" {
			serveDashboard(w, r)
			return
		}

		if r.URL.Path == "/logout" {
			handleLogout(w, r)
			return
		}

		if r.URL.Path == "/api/catalog" {
			handleCatalog(w, r)
			return
		}

		if r.URL.Path == "/api/repos" {
			handleRepos(w, r)
			return
		}

		if r.URL.Path == "/api/tags" {
			handleTags(w, r)
			return
		}

		user, ok := authenticate(w, r)
		if !ok {
			fmt.Println("not working with user", user)
			return
		}

		if !authorize(user, r) {
			fmt.Println("forbidden", user.Name, r.Method, r.URL.Path, user)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	certPath := "/certs/registry.crt"
	keyPath := "/certs/registry.key"

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		log.Fatalf("unable to ensure TLS certificate: %v", err)
	}

	log.Println("listening on :8443")
	log.Fatal(http.ListenAndServeTLS(
		":8443",
		certPath,
		keyPath,
		handler,
	))
}
