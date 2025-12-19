package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	upstream = mustParse("http://registry:5000")
	ldapCfg  = loadLDAPConfig()
)

const sessionTTL = 30 * time.Minute

type sessionData struct {
	User       *User
	Access     []Access
	Namespaces []string
	CreatedAt  time.Time
}

var (
	sessionMu sync.Mutex
	sessions  = map[string]sessionData{}
)

type User struct {
	Name          string
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type Access struct {
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type LDAPConfig struct {
	URL             string
	BaseDN          string
	UserFilter      string
	GroupAttribute  string
	GroupNamePrefix string
	UserMailDomain  string
	StartTLS        bool
	SkipTLSVerify   bool
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

func loadLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:             getEnv("LDAP_URL", "ldaps://ldap:389"),
		BaseDN:          getEnv("LDAP_BASE_DN", "dc=glauth,dc=com"),
		UserFilter:      getEnv("LDAP_USER_FILTER", "(uid=%s)"),
		GroupAttribute:  getEnv("LDAP_GROUP_ATTRIBUTE", "memberOf"),
		GroupNamePrefix: getEnv("LDAP_GROUP_PREFIX", "team"),
		UserMailDomain:  getEnv("LDAP_USER_DOMAIN", "@example.com"),
		StartTLS:        getEnvBool("LDAP_STARTTLS", false),
		SkipTLSVerify:   getEnvBool("LDAP_SKIP_TLS_VERIFY", true),
	}
}

func ldapAuthenticate(username, password string) (*User, error) {
	user, _, err := ldapAuthenticateAccess(username, password)
	return user, err
}

func ldapAuthenticateAccess(username, password string) (*User, []Access, error) {
	conn, err := dialLDAP(ldapCfg)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && ldapCfg.UserMailDomain != "" {
		domain := ldapCfg.UserMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		return nil, nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}

	filter := fmt.Sprintf(ldapCfg.UserFilter, username)
	searchReq := ldap.NewSearchRequest(
		ldapCfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, nil, fmt.Errorf("user %s not found", mail)
	}

	entry := sr.Entries[0]

	groups := entry.GetAttributeValues(ldapCfg.GroupAttribute)
	access, user := accessFromGroups(username, groups, ldapCfg.GroupNamePrefix)
	if user == nil {
		return nil, nil, fmt.Errorf("no authorized groups for %s", username)
	}

	return user, access, nil
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}))
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func accessFromGroups(username string, groups []string, prefix string) ([]Access, *User) {
	var selected *User
	var access []Access

	for _, g := range groups {
		groupName := groupNameFromDN(g)
		if prefix != "" && !strings.HasPrefix(groupName, prefix) {
			continue
		}

		ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(groupName)
		if !ok {
			continue
		}

		access = append(access, Access{
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		})

		candidate := &User{
			Name:          username,
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		}

		if selected == nil || morePermissive(candidate, selected) {
			selected = candidate
		}
	}

	return access, selected
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

func groupNameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}

	first := strings.TrimSpace(parts[0])
	firstLower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(firstLower, "cn="):
		return first[3:]
	case strings.HasPrefix(firstLower, "ou="):
		return first[3:]
	default:
		return dn
	}
}

func permissionsFromGroup(group string) (namespace string, pullOnly bool, deleteAllowed bool, ok bool) {
	switch {
	case strings.HasSuffix(group, "_read_write_delete"):
		ns := strings.TrimSuffix(group, "_read_write_delete")
		return ns, false, true, true
	case strings.HasSuffix(group, "_read_write"):
		ns := strings.TrimSuffix(group, "_read_write")
		return ns, false, false, true
	case strings.HasSuffix(group, "_read_only"):
		ns := strings.TrimSuffix(group, "_read_only")
		return ns, true, false, true
	default:
		// Bare group name defaults to read/write without delete
		return group, false, false, true
	}
}

func morePermissive(a, b *User) bool {
	if a.DeleteAllowed != b.DeleteAllowed {
		return a.DeleteAllowed
	}
	if a.PullOnly != b.PullOnly {
		return !a.PullOnly
	}
	return false
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "1" || v == "true" || v == "yes"
	}
	return def
}

func serveLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, landingHTML)
}

func extractCredentials(r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, loginHTML)
		return
	case http.MethodPost:
		username, password, ok, err := extractCredentials(r)
		if err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !ok {
			http.Error(w, "missing credentials", http.StatusBadRequest)
			return
		}

		user, access, err := ldapAuthenticateAccess(username, password)
		if err != nil {
			log.Printf("ldap auth failed for %s: %v", username, err)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		token := createSession(user, access)
		http.SetCookie(w, &http.Cookie{
			Name:     "cv_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

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

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	sess, ok := getSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	namespacesJSON, err := json.Marshal(sess.Namespaces)
	if err != nil {
		http.Error(w, "unable to render dashboard", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, dashboardHTML, html.EscapeString(sess.User.Name), string(namespacesJSON))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("cv_session")
	if err == nil && cookie.Value != "" {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
		sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "cv_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type repoInfo struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	if namespace == "" || !namespaceAllowed(sess.Namespaces, namespace) {
		http.Error(w, "namespace not allowed", http.StatusForbidden)
		return
	}

	repos, err := fetchCatalog(r.Context(), namespace)
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":     sess.User.Name,
		"namespace":    namespace,
		"repositories": repos,
	})
}

type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

type tagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func namespaceAllowed(allowed []string, namespace string) bool {
	for _, ns := range allowed {
		if ns == namespace {
			return true
		}
	}
	return false
}

func fetchCatalog(ctx context.Context, namespace string) ([]repoInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	catalogURL := upstream.ResolveReference(&url.URL{Path: "/v2/_catalog"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var cat catalogResponse
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, err
	}

	var repos []repoInfo
	prefix := namespace + "/"
	for _, repo := range cat.Repositories {
		if !strings.HasPrefix(repo, prefix) {
			continue
		}
		tagsURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/tags/list"})
		tagReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL.String(), nil)
		if err != nil {
			return nil, err
		}
		tagResp, err := client.Do(tagReq)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tagResp.Body)
		tagResp.Body.Close()
		if err != nil {
			return nil, err
		}
		if tagResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("tags status: %s", tagResp.Status)
		}
		var tags tagsResponse
		if err := json.Unmarshal(data, &tags); err != nil {
			return nil, err
		}
		repos = append(repos, repoInfo{Name: repo, Tags: tags.Tags})
	}

	return repos, nil
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault Enterprise</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 20% 20%, rgba(56,189,248,0.15), transparent 40%),
      radial-gradient(circle at 80% 0%, rgba(14,165,233,0.15), transparent 35%),
      var(--bg);
      color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
    .card { background:linear-gradient(160deg, rgba(15,23,42,0.96), rgba(2,6,23,0.96)); border:1px solid var(--line); border-radius:18px; padding:36px 40px; max-width:720px; width:100%; box-shadow:0 24px 70px rgba(0,0,0,0.4); }
    h1 { margin:8px 0 12px; font-size:34px; letter-spacing:0.5px; color:var(--accent); }
    p { margin:8px 0; line-height:1.5; }
    .tag { display:inline-block; padding:6px 10px; border-radius:999px; background:rgba(56,189,248,0.12); color:#bae6fd; font-size:12px; letter-spacing:0.4px; text-transform:uppercase; }
    .mono { font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; color:#cbd5e1; }
    a.button { display:inline-block; margin-top:18px; padding:10px 16px; border-radius:10px; background:var(--accent); color:#062238; text-decoration:none; font-weight:600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="tag">Container Registry Proxy</div>
    <h1>ContainerVault Enterprise</h1>
    <p>Secure gateway for your private Docker registry with per-namespace access control.</p>
    <p class="mono">Push &amp; pull via this endpoint:<br> <strong>https://skod.net</strong></p>
    <p class="mono">Ping: <strong>GET /v2/</strong><br> Namespaced access: <strong>/v2/&lt;team&gt;/...</strong></p>
    <a class="button" href="/login">Open Login</a>
  </div>
</body>
</html>
`

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault Enterprise</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 15% 15%, rgba(56,189,248,0.18), transparent 40%),
      radial-gradient(circle at 85% 5%, rgba(14,165,233,0.12), transparent 35%),
      var(--bg);
      color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
    .card { background:linear-gradient(160deg, rgba(15,23,42,0.96), rgba(2,6,23,0.96)); border:1px solid var(--line); border-radius:18px; padding:36px 40px; max-width:520px; width:100%; box-shadow:0 24px 70px rgba(0,0,0,0.4); }
    h1 { margin:0 0 12px; font-size:30px; color:var(--accent); }
    p { margin:8px 0; line-height:1.5; color:var(--muted); }
    form { display:grid; gap:14px; margin-top:18px; }
    label { font-size:13px; color:var(--muted); letter-spacing:0.3px; text-transform:uppercase; }
    input { background:#0b1224; border:1px solid var(--line); color:#e2e8f0; border-radius:10px; padding:10px 12px; font-size:15px; }
    button { border:0; border-radius:10px; padding:12px 14px; font-weight:600; background:var(--accent); color:#062238; cursor:pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ContainerVault Enterprise</h1>
    <p>Sign in to see your allowed namespaces and browse repository contents.</p>
    <form method="post" action="/login">
      <div>
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
      </div>
      <div>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>
`

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault Enterprise</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 10%% 20%%, rgba(56,189,248,0.16), transparent 40%%),
      radial-gradient(circle at 90%% 0%%, rgba(14,165,233,0.12), transparent 35%%),
      var(--bg);
      color:#e2e8f0; min-height:100vh; padding:32px; }
    h1 { margin:0 0 6px; font-size:28px; color:var(--accent); }
    p { margin:6px 0 18px; color:var(--muted); }
    .layout { display:grid; gap:18px; grid-template-columns: 260px 1fr; }
    .panel { border:1px solid var(--line); border-radius:16px; padding:16px; background:rgba(2,6,23,0.75); }
    .mono { font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; color:#cbd5e1; }
    .ns { padding:8px 10px; border-radius:10px; background:#0b1224; border:1px solid var(--line); margin-bottom:8px; font-size:14px; }
    .ns.active { border-color:var(--accent); color:#e2e8f0; }
    select { width:100%%; background:#0b1224; border:1px solid var(--line); color:#e2e8f0; border-radius:10px; padding:10px 12px; font-size:15px; }
    .repo { padding:10px 12px; border-radius:12px; border:1px solid var(--line); background:rgba(15,23,42,0.6); margin-bottom:12px; }
    .repo strong { color:#e2e8f0; }
    .tags { color:var(--muted); font-size:13px; margin-top:6px; }
    .topbar { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .logout { border:1px solid var(--line); background:#0b1224; color:#e2e8f0; padding:8px 12px; border-radius:10px; cursor:pointer; }
    @media (max-width: 800px) { .layout { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1>ContainerVault Enterprise</h1>
      <p>Welcome, %s. Select a namespace to browse repositories and tags.</p>
    </div>
    <form method="post" action="/logout">
      <button class="logout" type="submit">Logout</button>
    </form>
  </div>
  <div class="layout">
    <div class="panel">
      <div class="mono">Namespaces</div>
      <div id="namespaceList"></div>
    </div>
    <div class="panel">
      <div class="mono">Browse Containers</div>
      <div style="margin:12px 0;">
        <select id="namespaceSelect"></select>
      </div>
      <div id="catalogPanel">
        <p class="mono">Choose a namespace to load repositories.</p>
      </div>
    </div>
  </div>
  <script>
    (function () {
      const namespaces = %s;
      const list = document.getElementById('namespaceList');
      const select = document.getElementById('namespaceSelect');
      const panel = document.getElementById('catalogPanel');

      function escapeHTML(value) {
        return String(value).replace(/[&<>"']/g, function (ch) {
          const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
          return map[ch];
        });
      }

      function renderNamespaces() {
        if (!namespaces || namespaces.length === 0) {
          list.innerHTML = '<div class="mono">No namespaces assigned.</div>';
          select.innerHTML = '';
          return;
        }
        list.innerHTML = namespaces.map(function (ns, idx) {
          return '<div class="ns' + (idx === 0 ? ' active' : '') + '">' + escapeHTML(ns) + '</div>';
        }).join('');
        select.innerHTML = namespaces.map(function (ns) {
          return '<option value="' + escapeHTML(ns) + '">' + escapeHTML(ns) + '</option>';
        }).join('');
      }

      function renderCatalog(data) {
        if (!data.repositories || data.repositories.length === 0) {
          panel.innerHTML = '<p class="mono">No repositories found for this namespace.</p>';
          return;
        }
        panel.innerHTML = data.repositories.map(function (repo) {
          const tags = (repo.tags || []).join(', ') || 'no tags';
          return '<div class="repo">' +
            '<strong>' + escapeHTML(repo.name) + '</strong>' +
            '<div class="tags">' + escapeHTML(tags) + '</div>' +
            '</div>';
        }).join('');
      }

      async function loadCatalog(namespace) {
        panel.innerHTML = '<p class="mono">Loading repositories...</p>';
        try {
          const res = await fetch('/api/catalog?namespace=' + encodeURIComponent(namespace));
          const text = await res.text();
          if (!res.ok) {
            panel.innerHTML = '<p class="mono">' + escapeHTML(text) + '</p>';
            return;
          }
          let data;
          try {
            data = JSON.parse(text);
          } catch (err) {
            panel.innerHTML = '<p class="mono">Unexpected response.</p>';
            return;
          }
          renderCatalog(data);
        } catch (err) {
          panel.innerHTML = '<p class="mono">Unable to load catalog.</p>';
        }
      }

      select.addEventListener('change', function () {
        const ns = select.value;
        loadCatalog(ns);
        Array.prototype.forEach.call(list.children, function (child) {
          child.classList.toggle('active', child.textContent === ns);
        });
      });

      renderNamespaces();
      if (namespaces && namespaces.length > 0) {
        loadCatalog(namespaces[0]);
      }
    })();
  </script>
</body>
</html>
`

func GetUserGroups(
	l *ldap.Conn,
	userDN string,
	baseDN string,

) ([]string, error) {

	//userDN := fmt.Sprintf("cn=%s,%s", username, baseDN)

	filter := fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN))

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"cn"},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range res.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups, nil
}

func FindUserDN(
	l *ldap.Conn,
	baseDN string,
	login string,
) (string, error) {

	filter := fmt.Sprintf(
		"(|(uid=%s)(cn=%s)(mail=%s))",
		ldap.EscapeFilter(login),
		ldap.EscapeFilter(login),
		ldap.EscapeFilter(login),
	)

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{}, // DN only
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		return "", err
	}

	if len(res.Entries) != 1 {
		return "", fmt.Errorf("user not found or ambiguous")
	}

	return res.Entries[0].DN, nil
}
