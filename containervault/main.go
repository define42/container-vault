package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	upstream = mustParse("http://registry:5000")
)

// Simple user model (replace with LDAP later)
type User struct {
	Name          string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

var users = map[string]User{
	"alice": {Name: "alice", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
	"bob":   {Name: "bob", Namespace: "team2", PullOnly: true, DeleteAllowed: false},
}

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

func authenticate(w http.ResponseWriter, r *http.Request) (*User, bool) {
	fmt.Println(r.Header)
	user, pass, ok := r.BasicAuth()
	if !ok || pass == "" {
		fmt.Println("write header WWW-Authenticate")
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return nil, false
	}

	u, exists := users[user]
	if !exists {
		http.Error(w, "invalid user", http.StatusUnauthorized)
		return nil, false
	}

	return &u, true
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

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// ensureTLSCert creates a self-signed cert/key pair if either file is missing.
func ensureTLSCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}

	log.Printf("generating self-signed certificate at %s", certPath)
	return generateSelfSigned(certPath, keyPath)
}

func generateSelfSigned(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "registry",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"registry", "localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return err
	}

	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return err
	}

	return nil
}

func serveLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, landingHTML)
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault-Enterprise</title>
  <style>
    body { margin:0; font-family: "Segoe UI", sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .card { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:32px 36px; max-width:520px; box-shadow:0 20px 60px rgba(0,0,0,0.35); }
    h1 { margin:0 0 12px; font-size:32px; letter-spacing:0.5px; color:#38bdf8; }
    p { margin:8px 0; line-height:1.5; }
    .tag { display:inline-block; padding:6px 10px; border-radius:999px; background:rgba(56,189,248,0.12); color:#bae6fd; font-size:12px; letter-spacing:0.4px; text-transform:uppercase; }
    .mono { font-family: "SFMono-Regular", Consolas, monospace; color:#cbd5e1; }
  </style>
</head>
<body>
  <div class="card">
    <div class="tag">Container Registry Proxy</div>
    <h1>ContainerVault-Enterprise</h1>
    <p>Secure gateway for your private Docker registry with per-namespace access control.</p>
    <p class="mono">Push &amp; pull via this endpoint:<br> <strong>https://skod.net</strong></p>
    <p class="mono">Ping: <strong>GET /v2/</strong><br> Namespaced access: <strong>/v2/&lt;team&gt;/...</strong></p>
  </div>
</body>
</html>
`
