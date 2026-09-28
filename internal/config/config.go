// Package config loads and validates the Auth Gateway configuration.
//
// Security stance: a missing or empty required field is a fatal error. We never
// silently fall back to a "convenient" but dangerous default (for example an
// empty Redis password or plaintext token storage).
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Env variable names understood as overrides. GATEWAY_CONFIG is handled by the
// entrypoint; the rest are applied here after the YAML file is parsed.
const (
	EnvConfig    = "GATEWAY_CONFIG"
	EnvListen    = "GATEWAY_LISTEN"
	EnvIssuer    = "GATEWAY_ISSUER"
	EnvRedisAddr = "GATEWAY_REDIS_ADDR"
	EnvRedisDB   = "GATEWAY_REDIS_DB"
)

// ModeProtect only keeps identity in the session; no tokens are stored.
const ModeProtect = "protect"

// ModeProxy additionally stores tokens and injects a bearer token upstream.
const ModeProxy = "proxy"

// Config is the fully resolved gateway configuration.
type Config struct {
	Listen         string        `yaml:"listen"`
	Issuer         string        `yaml:"issuer"`
	LogoutRedirect string        `yaml:"logout_redirect"`
	Redis          RedisConfig   `yaml:"redis"`
	Session        SessionConfig `yaml:"session"`
	Token          TokenConfig   `yaml:"token"`
	Audit          AuditConfig   `yaml:"audit"`
	Apps           []AppConfig   `yaml:"apps"`

	tokenKey []byte
}

// RedisConfig describes the Redis connection. DB is a pointer so that "absent"
// is distinguishable from an explicit 0; absent becomes 2 per the spec.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	DB       *int   `yaml:"db"`
	Password string `yaml:"password"`
	Prefix   string `yaml:"prefix"`
}

// SessionConfig controls state and session lifetimes.
type SessionConfig struct {
	StateTTLMinutes int    `yaml:"state_ttl_minutes"`
	TTLHours        int    `yaml:"ttl_hours"`
	CookieSuffix    string `yaml:"cookie_suffix"`
}

// TokenConfig controls token encryption and local JWKS validation.
type TokenConfig struct {
	EncryptionKeyFile string `yaml:"encryption_key_file"`
	JWKSCacheHours    int    `yaml:"jwks_cache_hours"`
	ClockSkewMinutes  int    `yaml:"clock_skew_minutes"`
}

// AuditConfig points at the append-only audit log.
type AuditConfig struct {
	File          string `yaml:"file"`
	RetentionDays int    `yaml:"retention_days"`
}

// AppConfig is one protected site.
type AppConfig struct {
	ID          string   `yaml:"id"`
	Hosts       []string `yaml:"hosts"`
	Upstream    string   `yaml:"upstream"`
	APIUpstream string   `yaml:"api_upstream"`
	Mode        string   `yaml:"mode"`
	SecretFile  string   `yaml:"secret_file"`

	// ClientSecret is loaded from SecretFile, never serialized.
	ClientSecret string `yaml:"-"`
}

// Load reads YAML from path, applies environment overrides and validates.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config: empty config path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(false)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	c.applyEnv()
	if err := c.normalizeAndValidate(); err != nil {
		return nil, err
	}
	if err := c.loadSecrets(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv(EnvListen); v != "" {
		c.Listen = v
	}
	if v := os.Getenv(EnvIssuer); v != "" {
		c.Issuer = v
	}
	if v := os.Getenv(EnvRedisAddr); v != "" {
		c.Redis.Addr = v
	}
	if v := os.Getenv(EnvRedisDB); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Redis.DB = &n
		}
	}
}

func (c *Config) normalizeAndValidate() error {
	var errs []string

	if strings.TrimSpace(c.Listen) == "" {
		errs = append(errs, "listen is required")
	} else if err := requireLoopback(c.Listen); err != nil {
		errs = append(errs, err.Error())
	}

	if strings.TrimSpace(c.Issuer) == "" {
		errs = append(errs, "issuer is required")
	} else if u, err := url.Parse(c.Issuer); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, "issuer must be an absolute URL")
	} else {
		c.Issuer = strings.TrimRight(c.Issuer, "/")
	}

	if strings.TrimSpace(c.Redis.Addr) == "" {
		errs = append(errs, "redis.addr is required")
	}
	if c.Redis.DB == nil {
		db := 2 // spec: dedicated DB 2 by default
		c.Redis.DB = &db
	}
	if *c.Redis.DB < 0 || *c.Redis.DB > 15 {
		errs = append(errs, "redis.db must be within 0..15")
	}
	if strings.TrimSpace(c.Redis.Prefix) == "" {
		c.Redis.Prefix = "gw:"
	}

	if c.Session.StateTTLMinutes <= 0 {
		c.Session.StateTTLMinutes = 10
	}
	if c.Session.TTLHours <= 0 {
		c.Session.TTLHours = 168
	}
	if strings.TrimSpace(c.Session.CookieSuffix) == "" {
		c.Session.CookieSuffix = "_session"
	}
	if strings.ContainsAny(c.Session.CookieSuffix, " ;,=\"\\") {
		errs = append(errs, "session.cookie_suffix contains illegal characters")
	}

	if c.Token.JWKSCacheHours <= 0 {
		c.Token.JWKSCacheHours = 24
	}
	if c.Token.ClockSkewMinutes < 0 {
		errs = append(errs, "token.clock_skew_minutes must not be negative")
	}

	if len(c.Apps) == 0 {
		errs = append(errs, "at least one app is required")
	}

	seenID := map[string]bool{}
	seenHost := map[string]string{}
	needTokenKey := false
	for i := range c.Apps {
		a := &c.Apps[i]
		if strings.TrimSpace(a.ID) == "" {
			errs = append(errs, fmt.Sprintf("apps[%d].id is required", i))
		} else if seenID[a.ID] {
			errs = append(errs, fmt.Sprintf("duplicate app id %q", a.ID))
		} else {
			seenID[a.ID] = true
		}
		if !validCookieToken(a.ID) {
			errs = append(errs, fmt.Sprintf("apps[%d].id %q is not a valid cookie token", i, a.ID))
		}
		if len(a.Hosts) == 0 {
			errs = append(errs, fmt.Sprintf("app %q has no hosts", a.ID))
		}
		for _, h := range a.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				errs = append(errs, fmt.Sprintf("app %q has an empty host", a.ID))
				continue
			}
			if prev, ok := seenHost[h]; ok {
				errs = append(errs, fmt.Sprintf("host %q is claimed by both %q and %q", h, prev, a.ID))
			} else {
				seenHost[h] = a.ID
			}
		}
		if err := validateUpstream(a.ID, "upstream", a.Upstream); err != nil {
			errs = append(errs, err.Error())
		}
		switch a.Mode {
		case ModeProtect:
		case ModeProxy:
			needTokenKey = true
			if strings.TrimSpace(a.APIUpstream) == "" {
				a.APIUpstream = a.Upstream // default to the same origin
			}
			if err := validateUpstream(a.ID, "api_upstream", a.APIUpstream); err != nil {
				errs = append(errs, err.Error())
			}
		default:
			errs = append(errs, fmt.Sprintf("app %q has invalid mode %q (want protect|proxy)", a.ID, a.Mode))
		}
		if strings.TrimSpace(a.SecretFile) == "" {
			errs = append(errs, fmt.Sprintf("app %q is missing secret_file", a.ID))
		}
	}
	if needTokenKey && strings.TrimSpace(c.Token.EncryptionKeyFile) == "" {
		errs = append(errs, "token.encryption_key_file is required when any app uses mode: proxy")
	}
	if strings.TrimSpace(c.Audit.File) == "" {
		errs = append(errs, "audit.file is required")
	}
	if strings.TrimSpace(c.LogoutRedirect) == "" {
		c.LogoutRedirect = "/"
	}
	if !strings.HasPrefix(c.LogoutRedirect, "/") {
		errs = append(errs, "logout_redirect must be a site-absolute path")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// loadSecrets reads per-app client secrets and the token encryption key.
func (c *Config) loadSecrets() error {
	for i := range c.Apps {
		a := &c.Apps[i]
		b, err := os.ReadFile(a.SecretFile)
		if err != nil {
			return fmt.Errorf("config: app %q secret_file: %w", a.ID, err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return fmt.Errorf("config: app %q secret_file is empty", a.ID)
		}
		a.ClientSecret = s
	}
	if strings.TrimSpace(c.Token.EncryptionKeyFile) != "" {
		key, err := LoadKey(c.Token.EncryptionKeyFile)
		if err != nil {
			return err
		}
		c.tokenKey = key
	}
	return nil
}

// TokenKey returns the AES key material used to encrypt stored tokens.
func (c *Config) TokenKey() []byte { return c.tokenKey }

// LoadKey reads a key file and derives a fixed 32-byte AES key.
//
// Accepted forms: 64 hex chars, base64 (std or raw URL) decoding to >=16 bytes,
// or arbitrary text which is hashed with SHA-256. A missing file is an error:
// we never degrade to plaintext token storage.
func LoadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: token encryption key: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, errors.New("config: token encryption key file is empty")
	}
	if len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) >= 16 {
			sum := sha256.Sum256(k)
			return sum[:], nil
		}
	}
	sum := sha256.Sum256([]byte(s))
	return sum[:], nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %q must be host:port", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen %q must bind a loopback address (the gateway is only reachable via nginx)", addr)
	}
	return nil
}

func validateUpstream(appID, field, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("app %q is missing %s", appID, field)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("app %q %s must be an absolute URL", appID, field)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("app %q %s must use http or https", appID, field)
	}
	return nil
}

// validCookieToken reports whether s can appear in a cookie name per RFC 6265.
func validCookieToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r >= 0x7f {
			return false
		}
		switch r {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}
