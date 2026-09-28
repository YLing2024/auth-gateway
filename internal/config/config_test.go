package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const baseYAML = `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/auth-gateway-test/audit.log
apps:
  - id: android
    hosts: [android.example.com]
    upstream: http://127.0.0.1:8000
    mode: protect
    secret_file: %s
`

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadDefaultsRedisDB2(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "android.secret", "s3cr3t-value")
	cfg, err := loadYAML(t, strings.Replace(baseYAML, "%s", secret, 1))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Redis.DB == nil || *cfg.Redis.DB != 2 {
		t.Fatalf("redis.db = %v, want 2", cfg.Redis.DB)
	}
	if cfg.Redis.Prefix != "gw:" {
		t.Fatalf("prefix = %q, want gw:", cfg.Redis.Prefix)
	}
	if cfg.Session.StateTTLMinutes != 10 || cfg.Session.TTLHours != 168 {
		t.Fatalf("unexpected session defaults: %+v", cfg.Session)
	}
	if cfg.Apps[0].ClientSecret != "s3cr3t-value" {
		t.Fatal("client secret not loaded")
	}
}

func TestLoadRejectsNonLoopbackListen(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "android.secret", "x")
	body := strings.Replace(baseYAML, "127.0.0.1:18920", "0.0.0.0:18920", 1)
	body = strings.Replace(body, "%s", secret, 1)
	if _, err := loadYAML(t, body); err == nil {
		t.Fatal("expected non-loopback listen to be rejected")
	}
}

func TestLoadRejectsMissingFields(t *testing.T) {
	body := `
listen: 127.0.0.1:18920
redis:
  addr: 127.0.0.1:6379
apps: []
`
	if _, err := loadYAML(t, body); err == nil {
		t.Fatal("expected missing issuer/apps to be rejected")
	}
}

func TestProxyRequiresKeyFile(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "v2.secret", "x")
	body := `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/audit.log
apps:
  - id: v2
    hosts: [v2.example.com]
    upstream: http://127.0.0.1:7897
    mode: proxy
    secret_file: ` + secret + `
`
	if _, err := loadYAML(t, body); err == nil {
		t.Fatal("proxy mode without token.encryption_key_file must fail")
	}
}

func TestLoadKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "token.key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	k, err := LoadKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Fatalf("key length = %d, want 32", len(k))
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing key file must error, never fall back to plaintext")
	}
}
