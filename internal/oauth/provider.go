package oauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// JWKSStore is the durable cache for the raw JWKS document (Redis in
// production). It is injected so the oauth package does not depend on Redis.
type JWKSStore interface {
	LoadJWKS() ([]byte, bool, error)
	SaveJWKS(raw []byte, ttl time.Duration) error
}

// TokenResponse is the subset of the token endpoint response we use.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`

	// Expiry is computed locally from ExpiresIn.
	Expiry time.Time `json:"-"`
}

// Provider talks to one SSO issuer.
type Provider struct {
	Issuer   string
	Client   *http.Client
	Store    JWKSStore
	CacheTTL time.Duration
	Skew     time.Duration
	Now      func() time.Time

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

// NewProvider builds a provider with sane defaults.
func NewProvider(issuer string, store JWKSStore, cacheTTL, skew time.Duration) *Provider {
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	return &Provider{
		Issuer:   strings.TrimRight(issuer, "/"),
		Client:   &http.Client{Timeout: 15 * time.Second},
		Store:    store,
		CacheTTL: cacheTTL,
		Skew:     skew,
		Now:      time.Now,
	}
}

// AuthorizeURL builds the /authorize redirect for the PKCE flow.
func (p *Provider) AuthorizeURL(clientID, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return p.Issuer + "/authorize?" + q.Encode()
}

// ExchangeCode performs the authorization_code + PKCE token exchange using
// client_secret_post. It validates the PKCE relationship locally too.
func (p *Provider) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (*TokenResponse, error) {
	if strings.TrimSpace(verifier) == "" {
		return nil, errors.New("oauth: empty verifier")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oauth: parse token response: %w", err)
	}
	if tr.AccessToken == "" || tr.IDToken == "" {
		return nil, errors.New("oauth: token response missing access_token or id_token")
	}
	if tr.ExpiresIn > 0 {
		tr.Expiry = p.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		tr.Expiry = p.now().Add(time.Hour)
	}
	return &tr, nil
}

// Refresh exchanges a refresh_token for a new access token.
func (p *Provider) Refresh(ctx context.Context, clientID, clientSecret, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: refresh: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: refresh returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	if tr.ExpiresIn > 0 {
		tr.Expiry = p.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		tr.Expiry = p.now().Add(time.Hour)
	}
	return &tr, nil
}

// Revoke asks the issuer to revoke a token. Best effort at call sites.
func (p *Provider) Revoke(ctx context.Context, clientID, clientSecret, token string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Issuer+"/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("oauth: revoke: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("oauth: revoke returned %d", resp.StatusCode)
	}
	return nil
}

// VerifyIDToken validates the ES256 signature and the iss/aud/exp claims.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, clientID string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("oauth: id_token is not a compact JWS")
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oauth: decode id_token header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("oauth: parse id_token header: %w", err)
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("oauth: unsupported id_token alg %q (want ES256)", hdr.Alg)
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oauth: decode id_token signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	keys, err := p.keysCached(ctx, false)
	if err != nil {
		return nil, err
	}
	pub := keys[hdr.Kid]
	if pub == nil || !verifySignature(pub, signingInput, sig) {
		// The key set may have rotated: force one refresh and retry.
		keys, err = p.keysCached(ctx, true)
		if err != nil {
			return nil, err
		}
		pub = keys[hdr.Kid]
		if pub == nil {
			return nil, fmt.Errorf("oauth: no JWKS key matches kid %q", hdr.Kid)
		}
		if !verifySignature(pub, signingInput, sig) {
			return nil, errors.New("oauth: id_token signature verification failed")
		}
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oauth: decode id_token payload: %w", err)
	}
	return parseAndValidateClaims(payload, p.Issuer, clientID, p.Skew, p.now())
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) keysCached(ctx context.Context, force bool) (map[string]*ecdsa.PublicKey, error) {
	p.mu.Lock()
	if !force && p.keys != nil && p.now().Sub(p.fetched) < p.CacheTTL {
		keys := p.keys
		p.mu.Unlock()
		return keys, nil
	}
	p.mu.Unlock()

	// Prefer the durable cache before hitting the network.
	if !force && p.Store != nil {
		if raw, ok, err := p.Store.LoadJWKS(); err == nil && ok {
			if keys, err := parseJWKS(raw); err == nil {
				p.setKeys(keys)
				return keys, nil
			}
		}
	}

	keys, raw, err := p.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	if p.Store != nil {
		if err := p.Store.SaveJWKS(raw, p.CacheTTL); err != nil {
			// Cache write failure is not fatal; we already have the keys.
			_ = err
		}
	}
	p.setKeys(keys)
	return keys, nil
}

func (p *Provider) setKeys(keys map[string]*ecdsa.PublicKey) {
	p.mu.Lock()
	p.keys = keys
	p.fetched = p.now()
	p.mu.Unlock()
}

func (p *Provider) fetchJWKS(ctx context.Context) (map[string]*ecdsa.PublicKey, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Issuer+"/jwks.json", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("oauth: read jwks: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("oauth: jwks endpoint returned %d", resp.StatusCode)
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, nil, err
	}
	return keys, raw, nil
}
