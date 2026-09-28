package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PKCE holds an RFC 7636 verifier and its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a fresh verifier (32 random bytes, base64url) and the
// corresponding S256 challenge.
func NewPKCE() (PKCE, error) {
	v, err := RandomVerifier()
	if err != nil {
		return PKCE{}, err
	}
	return PKCE{Verifier: v, Challenge: ChallengeFor(v)}, nil
}

// RandomVerifier returns a new base64url (unpadded) 32-byte verifier.
func RandomVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: random verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeFor computes base64url(sha256(verifier)) with no padding.
func ChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomState returns a 16-byte hex state nonce.
func RandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: random state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RandomSID returns a 32-byte hex session identifier.
func RandomSID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: random sid: %w", err)
	}
	return hex.EncodeToString(b), nil
}
