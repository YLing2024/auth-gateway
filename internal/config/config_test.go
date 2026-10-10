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

const routesYAML = `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/auth-gateway-test/audit.log
apps:
  - id: quotahub
    hosts: [quotahub.example.com]
    secret_file: %s
    routes:
      - prefix: /api/
        upstream: http://127.0.0.1:5300
        auth: required
      - prefix: /
        upstream: http://127.0.0.1:5300
        auth: none
`

func TestRoutesAppNeedsNoAppLevelUpstream(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "quotahub.secret", "shh")
	cfg, err := loadYAML(t, strings.Replace(routesYAML, "%s", secret, 1))
	if err != nil {
		t.Fatalf("routes app without upstream/mode must load: %v", err)
	}
	a := cfg.Apps[0]
	if len(a.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(a.Routes))
	}
	if a.Mode != ModeProtect {
		t.Fatalf("mode = %q, want protect default", a.Mode)
	}
	if a.Routes[0].Auth != AuthRequired || a.Routes[1].Auth != AuthNone {
		t.Fatalf("unexpected auth values: %+v", a.Routes)
	}
}

func TestRoutesValidationErrors(t *testing.T) {
	base := `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/audit.log
apps:
  - id: q
    hosts: [q.example.com]
    secret_file: %s
    routes:
      - prefix: %s
        upstream: %s
        auth: %s
`
	cases := []struct {
		name, prefix, upstream, auth string
	}{
		{"prefix without slash", "api/", "http://127.0.0.1:5300", "required"},
		{"missing upstream", "/api/", "", "required"},
		{"relative upstream", "/api/", "/nope", "required"},
		{"bad auth", "/api/", "http://127.0.0.1:5300", "maybe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := write(t, dir, "q.secret", "x")
			body := strings.Replace(base, "%s", secret, 1)
			body = strings.Replace(body, "%s", tc.prefix, 1)
			body = strings.Replace(body, "%s", tc.upstream, 1)
			body = strings.Replace(body, "%s", tc.auth, 1)
			if _, err := loadYAML(t, body); err == nil {
				t.Fatalf("%s: expected validation error", tc.name)
			}
		})
	}
}

func TestAcceptBearerAudienceDefaultsAndValidation(t *testing.T) {
	base := `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/audit.log
apps:
  - id: q
    hosts: [q.example.com]
    upstream: http://127.0.0.1:5300
    mode: protect
    secret_file: %s
%s
`
	t.Run("defaults to app id", func(t *testing.T) {
		dir := t.TempDir()
		secret := write(t, dir, "q.secret", "x")
		body := strings.Replace(base, "%s", secret, 1)
		body = strings.Replace(body, "%s", "    accept_bearer: true", 1)
		cfg, err := loadYAML(t, body)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		a := cfg.Apps[0]
		if !a.AcceptBearer {
			t.Fatal("accept_bearer not set")
		}
		if len(a.BearerAudiences) != 1 || a.BearerAudiences[0] != "q" {
			t.Fatalf("bearer_audiences = %v, want [q]", a.BearerAudiences)
		}
	})
	t.Run("explicit audiences preserved", func(t *testing.T) {
		dir := t.TempDir()
		secret := write(t, dir, "q.secret", "x")
		body := strings.Replace(base, "%s", secret, 1)
		body = strings.Replace(body, "%s", "    accept_bearer: true\n    bearer_audiences: [admin, home-admin]", 1)
		cfg, err := loadYAML(t, body)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		got := cfg.Apps[0].BearerAudiences
		if len(got) != 2 || got[0] != "admin" || got[1] != "home-admin" {
			t.Fatalf("bearer_audiences = %v, want [admin home-admin]", got)
		}
	})
	t.Run("empty list is fatal", func(t *testing.T) {
		dir := t.TempDir()
		secret := write(t, dir, "q.secret", "x")
		body := strings.Replace(base, "%s", secret, 1)
		body = strings.Replace(body, "%s", "    accept_bearer: true\n    bearer_audiences: []", 1)
		if _, err := loadYAML(t, body); err == nil {
			t.Fatal("explicit empty bearer_audiences must be rejected")
		}
	})
	t.Run("empty entry is fatal", func(t *testing.T) {
		dir := t.TempDir()
		secret := write(t, dir, "q.secret", "x")
		body := strings.Replace(base, "%s", secret, 1)
		body = strings.Replace(body, "%s", "    bearer_audiences: [\"\"]", 1)
		if _, err := loadYAML(t, body); err == nil {
			t.Fatal("empty bearer_audiences entry must be rejected")
		}
	})
	t.Run("absent keeps safe default", func(t *testing.T) {
		dir := t.TempDir()
		secret := write(t, dir, "q.secret", "x")
		body := strings.Replace(base, "%s", secret, 1)
		body = strings.Replace(body, "%s", "", 1)
		cfg, err := loadYAML(t, body)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Apps[0].AcceptBearer {
			t.Fatal("accept_bearer must default to false")
		}
	})
}

func TestAppSiteURLUsesConfigOnly(t *testing.T) {
	a := &AppConfig{ID: "appa", Hosts: []string{" a.example.com "}}
	got, ok := a.SiteURL("/")
	if !ok || got != "https://a.example.com/" {
		t.Fatalf("SiteURL default = (%q, %v), want https://a.example.com/", got, ok)
	}
	if got, _ := a.SiteURL(""); got != "https://a.example.com/" {
		t.Fatalf("empty path = %q, want https://a.example.com/", got)
	}
	if got, _ := a.SiteURL("/deep?x=1"); got != "https://a.example.com/deep?x=1" {
		t.Fatalf("path = %q", got)
	}

	// Scheme comes from config and defaults to https; http is only used when
	// explicitly configured (local development).
	local := &AppConfig{ID: "appa", Hosts: []string{"localhost"}, Scheme: "http"}
	if got, _ := local.SiteURL("/"); got != "http://localhost/" {
		t.Fatalf("http scheme = %q", got)
	}
	bad := &AppConfig{ID: "appa", Hosts: []string{"a.example.com"}, Scheme: "ftp"}
	if _, ok := bad.SiteURL("/"); ok {
		t.Fatal("non-http(s) scheme must not build a URL")
	}
	// A relative path never yields a URL, and no request data is consulted.
	noHost := &AppConfig{ID: "appa"}
	if _, ok := noHost.SiteURL("/"); ok {
		t.Fatal("app without hosts must not build a URL")
	}
	if _, ok := (&AppConfig{ID: "x", Hosts: []string{"a.example.com"}}).SiteURL("relative"); ok {
		t.Fatal("relative path must not build a URL")
	}
}

func TestSchemeValidation(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "q.secret", "x")
	bad := `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/audit.log
apps:
  - id: q
    hosts: [q.example.com]
    upstream: http://127.0.0.1:5300
    mode: protect
    scheme: gopher
    secret_file: ` + secret + `
`
	if _, err := loadYAML(t, bad); err == nil {
		t.Fatal("invalid scheme must be rejected")
	}
}

func TestRoutesDuplicatePrefixRejected(t *testing.T) {
	dir := t.TempDir()
	secret := write(t, dir, "q.secret", "x")
	body := `
listen: 127.0.0.1:18920
issuer: https://auth.example.com
redis:
  addr: 127.0.0.1:6379
audit:
  file: /tmp/audit.log
apps:
  - id: q
    hosts: [q.example.com]
    secret_file: ` + secret + `
    routes:
      - prefix: /api/
        upstream: http://127.0.0.1:5300
        auth: required
      - prefix: /api/
        upstream: http://127.0.0.1:5300
        auth: none
`
	if _, err := loadYAML(t, body); err == nil {
		t.Fatal("duplicate route prefix must be rejected")
	}
}
