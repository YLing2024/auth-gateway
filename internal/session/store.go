package session

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// State is the one-time login intermediate state.
type State struct {
	App         string `json:"app"`
	Verifier    string `json:"verifier"`
	OriginalURL string `json:"original_url"`
	CreatedAt   int64  `json:"createdAt"`
}

// Session is the stored login session. Token fields are kept encrypted.
type Session struct {
	App          string `json:"app"`
	Sub          string `json:"sub"`
	Name         string `json:"name"`
	Exp          int64  `json:"exp"`
	AccessToken  string `json:"access_token,omitempty"`  // encrypted at rest
	RefreshToken string `json:"refresh_token,omitempty"` // encrypted at rest
	OriginalURL  string `json:"original_url,omitempty"`

	// SID is not serialized; it is the Redis key component.
	SID string `json:"-"`
}

// Store is the Redis-backed gateway state store.
type Store struct {
	r      *Redis
	prefix string
	crypt  *Crypt
	ttl    time.Duration
	cookie string // "_session"
}

// NewStore wires a store. crypt may be nil for protect-only deployments.
func NewStore(r *Redis, prefix string, crypt *Crypt, sessionTTL time.Duration, cookieSuffix string) *Store {
	return &Store{r: r, prefix: prefix, crypt: crypt, ttl: sessionTTL, cookie: cookieSuffix}
}

func (s *Store) key(parts ...string) string {
	k := s.prefix
	for i, p := range parts {
		if i == 0 {
			k += p
		} else {
			k += ":" + p
		}
	}
	return k
}

// ── state ────────────────────────────────────────────────────────────────

// PutState stores the login state with the configured TTL.
func (s *Store) PutState(state string, v State, ttl time.Duration) error {
	if v.CreatedAt == 0 {
		v.CreatedAt = time.Now().Unix()
	}
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.r.SetEX(s.key("state", state), string(body), ttl)
}

// TakeState atomically fetches and deletes the state (one-time use).
func (s *Store) TakeState(state string) (State, bool, error) {
	var out State
	raw, ok, err := s.r.GetDel(s.key("state", state))
	if err != nil || !ok {
		return out, false, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return out, false, fmt.Errorf("session: corrupt state: %w", err)
	}
	return out, true, nil
}

// ── session ──────────────────────────────────────────────────────────────

// PutSession encrypts token fields and stores the session.
func (s *Store) PutSession(sid string, v Session, ttl time.Duration) error {
	enc := v
	var err error
	if enc.AccessToken, err = s.crypt.Encrypt(v.AccessToken); err != nil {
		return err
	}
	if enc.RefreshToken, err = s.crypt.Encrypt(v.RefreshToken); err != nil {
		return err
	}
	body, err := json.Marshal(enc)
	if err != nil {
		return err
	}
	return s.r.SetEX(s.key("sess", sid), string(body), ttl)
}

// GetSession loads a session and slides its TTL to the full session lifetime.
func (s *Store) GetSession(sid string) (Session, bool, error) {
	var out Session
	raw, ok, err := s.r.Get(s.key("sess", sid))
	if err != nil || !ok {
		return out, false, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return out, false, fmt.Errorf("session: corrupt session: %w", err)
	}
	if out.AccessToken, err = s.crypt.Decrypt(out.AccessToken); err != nil {
		return out, false, err
	}
	if out.RefreshToken, err = s.crypt.Decrypt(out.RefreshToken); err != nil {
		return out, false, err
	}
	out.SID = sid
	if err := s.r.Expire(s.key("sess", sid), s.ttl); err != nil {
		return out, false, err
	}
	return out, true, nil
}

// DeleteSession removes a session immediately (logout).
func (s *Store) DeleteSession(sid string) error {
	return s.r.Del(s.key("sess", sid))
}

// ── revoked tokens ───────────────────────────────────────────────────────

// RevokeJTI blacklists a token id for at most its remaining lifetime.
func (s *Store) RevokeJTI(jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	return s.r.SetEX(s.key("revoked", jti), "1", ttl)
}

// IsRevoked reports whether a token id is blacklisted.
func (s *Store) IsRevoked(jti string) (bool, error) {
	_, ok, err := s.r.Get(s.key("revoked", jti))
	return ok, err
}

// ── jwks cache (implements oauth.JWKSStore) ──────────────────────────────

// LoadJWKS returns the cached JWKS document, if any.
func (s *Store) LoadJWKS() ([]byte, bool, error) {
	raw, ok, err := s.r.Get(s.key("jwks"))
	if err != nil || !ok {
		return nil, false, err
	}
	return []byte(raw), true, nil
}

// SaveJWKS persists the JWKS document for the given TTL.
func (s *Store) SaveJWKS(raw []byte, ttl time.Duration) error {
	return s.r.SetEX(s.key("jwks"), string(raw), ttl)
}

// ── low-level command helpers ────────────────────────────────────────────

func (r *Redis) Get(key string) (string, bool, error) {
	v, err := r.Do("GET", key)
	if err != nil {
		return "", false, err
	}
	if v == nil {
		return "", false, nil
	}
	s, _ := v.(string)
	return s, true, nil
}

func (r *Redis) GetDel(key string) (string, bool, error) {
	v, err := r.Do("GETDEL", key)
	if err != nil {
		return "", false, err
	}
	if v == nil {
		return "", false, nil
	}
	s, _ := v.(string)
	return s, true, nil
}

func (r *Redis) SetEX(key, val string, ttl time.Duration) error {
	secs := int(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	_, err := r.Do("SET", key, val, "EX", strconv.Itoa(secs))
	return err
}

func (r *Redis) Del(keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	args := append([]string{"DEL"}, keys...)
	_, err := r.Do(args...)
	return err
}

func (r *Redis) Expire(key string, ttl time.Duration) error {
	secs := int(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	_, err := r.Do("EXPIRE", key, strconv.Itoa(secs))
	return err
}
