package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticateWithGlauthConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")
	ldapCfg = loadLDAPConfig()

	u, err := ldapAuthenticate("hackers", "dogood")
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
	if u.Namespace != "team1" || u.PullOnly || !u.DeleteAllowed {
		t.Fatalf("unexpected permissions: %+v", u)
	}
}

func TestLDAPAuthenticateJohndoeSingleNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")
	prevCfg := ldapCfg
	ldapCfg = loadLDAPConfig()
	t.Cleanup(func() {
		ldapCfg = prevCfg
	})

	u, access, err := ldapAuthenticateAccess("johndoe", "dogood")
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}

	namespaces := make(map[string]struct{}, len(access))
	for _, entry := range access {
		namespaces[entry.Namespace] = struct{}{}
	}
	if len(namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d: %+v", len(namespaces), access)
	}
	if _, ok := namespaces["team10"]; !ok {
		t.Fatalf("expected namespace team10, got %+v", access)
	}
	if u.Namespace != "team10" || !u.PullOnly || u.DeleteAllowed {
		t.Fatalf("unexpected permissions: %+v", u)
	}
}

func TestProxyPushPullViaDocker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	network, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	defer network.Remove(ctx) //nolint:errcheck
	netName := network.Name

	ldapURL, stopLDAP := startGlauth(ctx, t, netName)
	defer stopLDAP()

	registryHost, stopRegistry := startRegistry(ctx, t, netName)
	defer stopRegistry()

	certDir := tempDirInRepo(t, "proxy-certs-")
	certPath := filepath.Join(certDir, "registry.crt")
	keyPath := filepath.Join(certDir, "registry.key")
	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("create certs: %v", err)
	}
	proxyHost, stopProxy := startProxy(ctx, t, netName, certDir)
	defer stopProxy()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")
	ldapCfg = loadLDAPConfig()

	dockerConfig := tempDirInRepo(t, "docker-config-")
	addDockerTrust(t, dockerConfig, proxyHost, filepath.Join(certDir, "registry.crt"))
	writeDockerAuth(t, dockerConfig, proxyHost, "hackers", "dogood")

	srcImage := ensureBaseImage(t, dockerConfig, "busybox:latest")
	target := fmt.Sprintf("%s/team1/integration:latest", proxyHost)

	dockerTag(t, dockerConfig, srcImage, target)
	dockerPush(t, dockerConfig, target)

	dockerRmi(t, dockerConfig, target)
	dockerPull(t, dockerConfig, target)

	_ = registryHost
}

func TestCvRouterProxyWithLDAP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startGlauth(ctx, t, "")
	defer stopLDAP()

	registryHost, stopRegistry := startRegistry(ctx, t, "")
	defer stopRegistry()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")
	prevCfg := ldapCfg
	ldapCfg = loadLDAPConfig()
	t.Cleanup(func() {
		ldapCfg = prevCfg
	})

	prevUpstream := upstream
	upstream = mustParse("http://" + registryHost)
	t.Cleanup(func() {
		upstream = prevUpstream
	})

	server := httptest.NewServer(cvRouter())
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	doRequest := func(client *http.Client, method, path, user, pass string, body io.Reader, headers map[string]string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		if user != "" || pass != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}

	accessCases := []struct {
		name       string
		method     string
		path       string
		user       string
		pass       string
		wantStatus int
	}{
		{"ping", http.MethodGet, "/v2/", "hackers", "dogood", http.StatusOK},
		{"wrong namespace", http.MethodGet, "/v2/something", "hackers", "dogood", http.StatusForbidden},
		{"dashboard without auth", http.MethodGet, "/dashboard", "", "", http.StatusUnauthorized},
		{"bad password", http.MethodGet, "/v2/", "hackers", "wrongpass", http.StatusUnauthorized},
		{"bad user", http.MethodGet, "/v2/something", "wronguser", "dogood", http.StatusUnauthorized},
		{"empty password", http.MethodGet, "/v2/", "hackers", "", http.StatusUnauthorized},
		{"empty username and password", http.MethodGet, "/v2/", "", "", http.StatusUnauthorized},
		{"empty password", http.MethodGet, "/v2/", "", "dogood", http.StatusUnauthorized},
	}
	for _, tc := range accessCases {
		status, body := doRequest(client, tc.method, tc.path, tc.user, tc.pass, nil, nil)
		if status != tc.wantStatus {
			t.Fatalf("expected %d for %s, got %d: %s", tc.wantStatus, tc.name, status, body)
		}
	}

	loginClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	postLogin := func(values url.Values) (int, string) {
		t.Helper()
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		return doRequest(loginClient, http.MethodPost, "/login", "", "", strings.NewReader(values.Encode()), headers)
	}

	form := url.Values{}
	form.Set("username", "hackers")
	form.Set("password", "dogood")
	loginReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new login request: %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp, err := loginClient.Do(loginReq)
	if err != nil {
		t.Fatalf("do login request: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("expected 303 for login, got %d: %s", loginResp.StatusCode, string(body))
	}
	if loc := loginResp.Header.Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
	}
	if !strings.Contains(loginResp.Header.Get("Set-Cookie"), "cv_session=") {
		t.Fatalf("expected session cookie on login")
	}

	badForm := url.Values{}
	badForm.Set("username", "hackers")
	badForm.Set("password", "wrongpass")
	badStatus, badBody := postLogin(badForm)
	if badStatus != http.StatusOK {
		t.Fatalf("expected 200 for bad login page, got %d: %s", badStatus, badBody)
	}
	if !strings.Contains(badBody, "Invalid credentials.") {
		t.Fatalf("expected invalid credentials message on login failure")
	}

	emptyForm := url.Values{}
	emptyForm.Set("username", "hackers")
	emptyForm.Set("password", "")
	emptyStatus, emptyBody := postLogin(emptyForm)
	if emptyStatus != http.StatusOK {
		t.Fatalf("expected 200 for empty login page, got %d: %s", emptyStatus, emptyBody)
	}
	if !strings.Contains(emptyBody, "Missing credentials.") {
		t.Fatalf("expected missing credentials message on empty login")
	}
}

func startGlauth(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "testldap", "default-config.cfg")
	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"ldap"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("ldaps://%s:%s", host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func startRegistry(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForListeningPort("5000/tcp").WithStartupTimeout(1 * time.Minute),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"registry"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start registry: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("registry host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5000/tcp")
	if err != nil {
		t.Fatalf("registry port: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.Port()), func() {
		_ = container.Terminate(context.Background())
	}
}

func startProxy(ctx context.Context, t *testing.T, network, certDir string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    ".",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"8443/tcp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: certDir, ContainerFilePath: "/certs", FileMode: 0o755},
		},
		WaitingFor: wait.ForLog("listening on :8443").
			WithStartupTimeout(2 * time.Minute).
			WithPollInterval(2 * time.Second),
	}

	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"proxy"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("proxy host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8443/tcp")
	if err != nil {
		t.Fatalf("proxy port: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.Port()), func() {
		_ = container.Terminate(context.Background())
	}
}

func addDockerTrust(t *testing.T, configDir, registry, certPath string) {
	t.Helper()

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "certs.d", registry), 0o755); err != nil {
		t.Fatalf("mk cert dir: %v", err)
	}
	dest := filepath.Join(configDir, "certs.d", registry, "ca.crt")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
}

func writeDockerAuth(t *testing.T, configDir, registry, user, pass string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, pass)))
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mk config dir: %v", err)
	}
	cfg := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"},"https://%s":{"auth":"%s"}}}`, registry, auth, registry, auth)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func ensureBaseImage(t *testing.T, configDir, image string) string {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "pull", image)
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker pull %s: %v", image, err)
	}
	return image
}

func dockerTag(t *testing.T, configDir, src, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "tag", src, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker tag: %v\n%s", err, string(out))
	}
}

func dockerPush(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "push", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker push: %v\n%s", err, string(out))
	}
}

func dockerRmi(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "rmi", "-f", target)
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker rmi %s: %v", target, err)
	}
}

func dockerPull(t *testing.T, configDir, target string) {
	t.Helper()
	cmd := exec.Command("docker", "--config", configDir, "pull", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker pull: %v\n%s", err, string(out))
	}
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

func tempDirInRepo(t *testing.T, prefix string) string {
	t.Helper()
	base := pathRelative(t, "..", "tmp")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mk temp base: %v", err)
	}
	dir, err := os.MkdirTemp(base, prefix)
	if err != nil {
		t.Fatalf("mk temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
