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

// AuthRequired means the route behaves like a fully protected app: session
// required, 302/401 split, identity headers injected.
const AuthRequired = "required"

// AuthNone means the route is public: no session is created or read and no
// identity headers are injected (forged ones are still stripped).
const AuthNone = "none"

// Config is the fully resolved gateway configuration.
type Config struct {
	Listen         string            `yaml:"listen"`
	Issuer         string            `yaml:"issuer"`
	LogoutRedirect string            `yaml:"logout_redirect"`
	Redis          RedisConfig       `yaml:"redis"`
	Session        SessionConfig     `yaml:"session"`
	Token          TokenConfig       `yaml:"token"`
	Audit          AuditConfig       `yaml:"audit"`
	Backchannel    BackchannelConfig `yaml:"backchannel"`
	Apps           []AppConfig       `yaml:"apps"`

	tokenKey         []byte
	backchannelToken []byte
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

// BackchannelConfig configures the loopback endpoint the auth centre calls
// after a global logout to tell the gateway to drop every session from one
// login. Authentication reuses the auth centre's shared internal token file.
type BackchannelConfig struct {
	// InternalTokenFile is the same shared secret file the auth centre writes
	// (default <DATA_DIR>/internal-token, 0600). Empty means the endpoint can
	// never authenticate: it fails closed with 401.
	InternalTokenFile string `yaml:"internal_token_file"`
	// Enabled gates the endpoint. Absent defaults to true; false makes the
	// endpoint return 404 (grey release / rollback).
	Enabled *bool `yaml:"enabled"`
}

// AppConfig is one protected site.
//
// Without Routes the whole app is one protected upstream (legacy behaviour,
// byte-for-byte unchanged). With Routes only the listed path prefixes are
// proxied, each with its own upstream and auth mode.
type AppConfig struct {
	ID          string   `yaml:"id"`
	Hosts       []string `yaml:"hosts"`
	Upstream    string   `yaml:"upstream"`
	APIUpstream string   `yaml:"api_upstream"`
	Mode        string   `yaml:"mode"`
	SecretFile  string   `yaml:"secret_file"`
	Routes      []Route  `yaml:"routes"`

	// Scheme is the public scheme used to build absolute post-logout return
	// URLs. It must be http or https and defaults to https; http exists only
	// for local development. Production sites are always https.
	Scheme string `yaml:"scheme"`

	// AcceptBearer makes protected requests accept a client-presented
	// Authorization: Bearer access token (native app / CLI channel). Disabled
	// by default so an app that omits the field behaves exactly as before.
	AcceptBearer bool `yaml:"accept_bearer"`
	// BearerAudiences are the aud values accepted for client bearer tokens.
	// Absent means [app.id]; an explicitly empty list is a fatal config error
	// (we never silently accept any audience).
	BearerAudiences []string `yaml:"bearer_audiences"`

	// bearerAudiencesSet records whether bearer_audiences appeared in the YAML,
	// which distinguishes "absent" (default) from an explicit empty list.
	bearerAudiencesSet bool

	// ClientSecret is loaded from SecretFile, never serialized.
	ClientSecret string `yaml:"-"`
}

// UnmarshalYAML decodes an app while remembering whether bearer_audiences was
// present. A plain []string cannot tell absent from "[]", and the two must be
// treated differently (default to [id] vs. a fatal error).
func (a *AppConfig) UnmarshalYAML(value *yaml.Node) error {
	type plain AppConfig // avoid recursing into this method
	var p plain
	if err := value.Decode(&p); err != nil {
		return err
	}
	*a = AppConfig(p)
	if value.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(value.Content); i += 2 {
			if value.Content[i].Value == "bearer_audiences" {
				a.bearerAudiencesSet = true
			}
		}
	}
	return nil
}

// Route is one path-prefix dispatch entry inside an app. The longest matching
// prefix wins; equal-length prefixes fall back to config order.
type Route struct {
	Prefix   string `yaml:"prefix"`
	Upstream string `yaml:"upstream"`
	Auth     string `yaml:"auth"` // required | none
}

// SiteURL builds an absolute URL for path on the app's first configured host
// using the app's scheme (default https). It only ever uses configuration, so
// it is immune to Host / X-Forwarded-Host injection and open redirects. ok is
// false when the app has no usable host or path is not site-absolute.
func (a *AppConfig) SiteURL(path string) (string, bool) {
	scheme := strings.ToLower(strings.TrimSpace(a.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if len(a.Hosts) == 0 {
		return "", false
	}
	host := strings.ToLower(strings.TrimSpace(a.Hosts[0]))
	if host == "" {
		return "", false
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	return scheme + "://" + host + path, true
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
		if len(a.Routes) == 0 {
			// Legacy whole-site app: exactly the pre-routes validation.
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
		} else {
			// Path-routed app. mode is optional and defaults to protect; an
			// app-level upstream is optional here (routes carry their own).
			seenPrefix := map[string]bool{}
			for j := range a.Routes {
				rt := &a.Routes[j]
				if !strings.HasPrefix(rt.Prefix, "/") {
					errs = append(errs, fmt.Sprintf("app %q routes[%d].prefix %q must start with /", a.ID, j, rt.Prefix))
				} else if seenPrefix[rt.Prefix] {
					errs = append(errs, fmt.Sprintf("app %q has duplicate route prefix %q", a.ID, rt.Prefix))
				} else {
					seenPrefix[rt.Prefix] = true
				}
				if err := validateUpstream(a.ID, fmt.Sprintf("routes[%d].upstream", j), rt.Upstream); err != nil {
					errs = append(errs, err.Error())
				}
				switch rt.Auth {
				case AuthRequired, AuthNone:
				default:
					errs = append(errs, fmt.Sprintf("app %q routes[%d].auth %q is invalid (want required|none)", a.ID, j, rt.Auth))
				}
			}
			if strings.TrimSpace(a.Upstream) != "" {
				if err := validateUpstream(a.ID, "upstream", a.Upstream); err != nil {
					errs = append(errs, err.Error())
				}
			}
			switch a.Mode {
			case "":
				a.Mode = ModeProtect
			case ModeProtect:
			case ModeProxy:
				needTokenKey = true
			default:
				errs = append(errs, fmt.Sprintf("app %q has invalid mode %q (want protect|proxy)", a.ID, a.Mode))
			}
		}
		if strings.TrimSpace(a.SecretFile) == "" {
			errs = append(errs, fmt.Sprintf("app %q is missing secret_file", a.ID))
		}

		if s := strings.ToLower(strings.TrimSpace(a.Scheme)); s != "" {
			if s != "http" && s != "https" {
				errs = append(errs, fmt.Sprintf("app %q has invalid scheme %q (want http|https)", a.ID, a.Scheme))
			} else {
				a.Scheme = s
			}
		}

		// Client bearer tokens: an absent audience list defaults to [app.id];
		// an explicit empty list is rejected rather than accepting any aud.
		if a.bearerAudiencesSet && len(a.BearerAudiences) == 0 {
			errs = append(errs, fmt.Sprintf("app %q bearer_audiences must not be empty (omit the field to default to [%s])", a.ID, a.ID))
		}
		if !a.bearerAudiencesSet {
			a.BearerAudiences = []string{a.ID}
		}
		for k, aud := range a.BearerAudiences {
			if strings.TrimSpace(aud) == "" {
				errs = append(errs, fmt.Sprintf("app %q bearer_audiences[%d] is empty", a.ID, k))
			}
		}
	}
	if needTokenKey && strings.TrimSpace(c.Token.EncryptionKeyFile) == "" {
		errs = append(errs, "token.encryption_key_file is required when any app uses mode: proxy")
	}
	if strings.TrimSpace(c.Audit.File) == "" {
		errs = append(errs, "audit.file is required")
	}
	if c.Backchannel.Enabled == nil {
		enabled := true // default on; only an explicit false disables the endpoint
		c.Backchannel.Enabled = &enabled
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
	if p := strings.TrimSpace(c.Backchannel.InternalTokenFile); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("config: backchannel.internal_token_file: %w", err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return errors.New("config: backchannel.internal_token_file is empty")
		}
		c.backchannelToken = []byte(s)
	}
	return nil
}

// BackchannelEnabled reports whether the back-channel logout endpoint is live.
func (c *Config) BackchannelEnabled() bool {
	return c.Backchannel.Enabled != nil && *c.Backchannel.Enabled
}

// BackchannelToken returns the shared internal token bytes (nil when unset).
func (c *Config) BackchannelToken() []byte { return c.backchannelToken }

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
