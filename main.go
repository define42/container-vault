package main

import (
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	_ = mime.AddExtensionType(".js", "application/javascript")
	staticDir := resolveStaticDir()

	// Use single-host reverse proxy to forward traffic to the registry
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Host = upstream.Host
			pr.SetXForwarded()
		},
	}

	proxy.FlushInterval = -1 // important for streaming blobs

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			path := strings.TrimPrefix(r.URL.Path, "/static/")
			if strings.HasSuffix(path, ".js") {
				w.Header().Set("Content-Type", "application/javascript")
			}
			setNoCacheHeaders(w)
			http.ServeFile(w, r, filepath.Join(staticDir, path))
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if r.URL.Path == "/login" {
			handleLogin(w, r)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/api/dashboard" {
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

		if r.URL.Path == "/api/taginfo" {
			handleTagInfo(w, r)
			return
		}

		if r.URL.Path == "/api/taglayers" {
			handleTagLayers(w, r)
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
	server := &http.Server{
		Addr:         ":8443",
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

func resolveStaticDir() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Join(filepath.Dir(exe), "static")
		if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
			return dir
		}
	}
	return "./static"
}
