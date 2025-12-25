package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func TestEnsureTLSCertCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "registry.crt")
	keyPath := filepath.Join(dir, "registry.key")

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected cert file, got %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file, got %v", err)
	}

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert again: %v", err)
	}
}

func TestLoadCertmagicConfigDisabled(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	_, enabled, err := loadCertmagicConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled {
		t.Fatalf("expected certmagic disabled")
	}
}

func TestLoadCertmagicConfigRequiresDomains(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	_, enabled, err := loadCertmagicConfig()
	if err == nil {
		t.Fatalf("expected error for missing domains")
	}
	if enabled {
		t.Fatalf("expected certmagic disabled on error")
	}
}

func TestLoadCertmagicConfigParsing(t *testing.T) {
	t.Setenv("CERTMAGIC_DOMAINS", "example.com, registry.example.com ")
	t.Setenv("CERTMAGIC_EMAIL", "ops@example.com")
	t.Setenv("CERTMAGIC_CA", "https://acme.local/directory")
	t.Setenv("CERTMAGIC_HTTP_PORT", "8080")
	t.Setenv("CERTMAGIC_TLS_ALPN_PORT", "8443")

	cfg, enabled, err := loadCertmagicConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0] != "example.com" || cfg.Domains[1] != "registry.example.com" {
		t.Fatalf("unexpected domains: %v", cfg.Domains)
	}
	if cfg.Email != "ops@example.com" || cfg.CA != "https://acme.local/directory" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.AltHTTPPort != 8080 || cfg.AltTLSALPNPort != 8443 {
		t.Fatalf("unexpected ports: %#v", cfg)
	}
}

func TestCertmagicTLSConfigDisabled(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	cfg, enabled, err := certmagicTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled {
		t.Fatalf("expected certmagic disabled")
	}
	if cfg != nil {
		t.Fatalf("expected nil tls config")
	}
}

func TestCertmagicTLSConfigCARootError(t *testing.T) {
	restoreCertmagicDefaults(t)
	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "example.com")
	t.Setenv("CERTMAGIC_CA_ROOT", filepath.Join(t.TempDir(), "missing.pem"))

	cfg, enabled, err := certmagicTLSConfig()
	if err == nil {
		t.Fatalf("expected error for missing CA root")
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if cfg != nil {
		t.Fatalf("expected nil tls config")
	}
}

func TestCertmagicTLSConfigAppliesCARootAndStorage(t *testing.T) {
	restoreCertmagicDefaults(t)
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "root.pem")
	keyPath := filepath.Join(certDir, "root.key")
	caCert, caKey := writeTestCA(t, certPath, keyPath)

	storagePath := filepath.Join(t.TempDir(), "certmagic")

	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "example.com")
	t.Setenv("CERTMAGIC_CA_ROOT", certPath)
	t.Setenv("CERTMAGIC_STORAGE", storagePath)

	origTLS := certmagicTLS
	certmagicTLS = func(domains []string) (*tls.Config, error) {
		if len(domains) != 1 || domains[0] != "example.com" {
			t.Fatalf("unexpected domains: %v", domains)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	t.Cleanup(func() {
		certmagicTLS = origTLS
	})

	cfg, enabled, err := certmagicTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if cfg == nil {
		t.Fatalf("expected tls config")
	}

	storage, ok := certmagic.Default.Storage.(*certmagic.FileStorage)
	if !ok {
		t.Fatalf("expected file storage, got %T", certmagic.Default.Storage)
	}
	if storage.Path != storagePath {
		t.Fatalf("expected storage path %q, got %q", storagePath, storage.Path)
	}

	roots := certmagic.DefaultACME.TrustedRoots
	if roots == nil {
		t.Fatalf("expected trusted roots")
	}

	leaf := generateLeafCert(t, caCert, caKey, "example.com")
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "example.com",
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("expected CA root to be added to trusted pool: %v", err)
	}
}

func writeTestCA(t *testing.T, certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certOut, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		t.Fatalf("write CA key: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, priv
}

func generateLeafCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, dnsName string) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{dnsName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

func restoreCertmagicDefaults(t *testing.T) {
	t.Helper()
	prevEmail := certmagic.DefaultACME.Email
	prevCA := certmagic.DefaultACME.CA
	prevAltHTTP := certmagic.DefaultACME.AltHTTPPort
	prevAltTLS := certmagic.DefaultACME.AltTLSALPNPort
	prevRoots := certmagic.DefaultACME.TrustedRoots
	prevStorage := certmagic.Default.Storage

	t.Cleanup(func() {
		certmagic.DefaultACME.Email = prevEmail
		certmagic.DefaultACME.CA = prevCA
		certmagic.DefaultACME.AltHTTPPort = prevAltHTTP
		certmagic.DefaultACME.AltTLSALPNPort = prevAltTLS
		certmagic.DefaultACME.TrustedRoots = prevRoots
		certmagic.Default.Storage = prevStorage
	})
}
