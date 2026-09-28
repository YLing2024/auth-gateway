package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Crypt encrypts token material at rest with AES-256-GCM.
type Crypt struct {
	aead cipher.AEAD
}

// NewCrypt builds a Crypt from a raw AES key (16/24/32 bytes).
func NewCrypt(key []byte) (*Crypt, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("session: token key must be 16/24/32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("session: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: gcm: %w", err)
	}
	return &Crypt{aead: aead}, nil
}

// Encrypt returns base64url(nonce || ciphertext). Empty input stays empty.
func (c *Crypt) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if c == nil {
		return "", errors.New("session: no token encryption key configured")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("session: nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (c *Crypt) Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if c == nil {
		return "", errors.New("session: encrypted token present but no key configured")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("session: decode token: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("session: token ciphertext too short")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("session: decrypt token: %w", err)
	}
	return string(plain), nil
}
