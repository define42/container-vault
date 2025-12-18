package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
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

func TestProxyPushPullViaDocker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	netName := fmt.Sprintf("cvnet-%d", time.Now().UnixNano())
	network, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{Name: netName},
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	defer network.Remove(ctx) //nolint:errcheck

	ldapURL, stopLDAP := startGlauth(ctx, t, netName)
	defer stopLDAP()

	registryHost, stopRegistry := startRegistry(ctx, t, netName)
	defer stopRegistry()

	certDir := t.TempDir()
	proxyHost, stopProxy := startProxy(ctx, t, netName, certDir)
	defer stopProxy()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")
	ldapCfg = loadLDAPConfig()

	dockerConfig := t.TempDir()
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

func startGlauth(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "..", "testldap", "default-config.cfg")
	cert := pathRelative(t, "..", "testldap", "cert.pem")
	key := pathRelative(t, "..", "testldap", "key.pem")

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(cfg, "/app/config/config.cfg"),
			testcontainers.BindMount(cert, "/app/config/cert.pem"),
			testcontainers.BindMount(key, "/app/config/key.pem"),
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
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(certDir, "/certs"),
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
	if err := os.WriteFile(dest, data, 0o644); err != nil {
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
	_ = cmd.Run() // ignore error if already present
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
	cmd.Run() // ignore errors if missing
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
