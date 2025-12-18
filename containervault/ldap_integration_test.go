package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticateWithGlauthConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t)
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

func startGlauth(ctx context.Context, t *testing.T) (string, func()) {
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
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
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

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}
