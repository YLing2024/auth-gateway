package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Claims are the id_token claims the gateway relies on.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	Name     string
	JTI      string
	Expiry   time.Time
	IssuedAt time.Time
}

type rawClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Name     string          `json:"name"`
	JTI      string          `json:"jti"`
	Expiry   json.Number     `json:"exp"`
	NotBef   json.Number     `json:"nbf"`
	IssuedAt json.Number     `json:"iat"`
}

func (r rawClaims) audience() ([]string, error) {
	if len(r.Audience) == 0 {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(r.Audience, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(r.Audience, &many); err != nil {
		return nil, errors.New("oauth: id_token aud is neither string nor array")
	}
	return many, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, fmt.Errorf("oauth: unsupported key type %q", k.Kty)
	}
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("oauth: unsupported curve %q", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("oauth: bad jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("oauth: bad jwk y: %w", err)
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("oauth: jwk point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseJWKS(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("oauth: parse jwks: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("oauth: jwks has no keys")
	}
	out := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for i, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip unusable keys; a later key may match
		}
		id := k.Kid
		if id == "" {
			id = fmt.Sprintf("#%d", i)
		}
		out[id] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("oauth: jwks has no usable EC P-256 keys")
	}
	return out, nil
}

// verifySignature checks an ES256 signature over signingInput with the key
// selected by kid.
func verifySignature(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, sum[:], r, s)
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
}

// parseAndValidateClaims validates iss/aud/exp with the given clock skew.
func parseAndValidateClaims(payload []byte, issuer, clientID string, skew time.Duration, now time.Time) (*Claims, error) {
	var rc rawClaims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("oauth: parse id_token claims: %w", err)
	}
	issuer = strings.TrimRight(issuer, "/")
	if rc.Issuer != issuer {
		return nil, fmt.Errorf("oauth: id_token issuer %q does not match %q", rc.Issuer, issuer)
	}
	aud, err := rc.audience()
	if err != nil {
		return nil, err
	}
	found := false
	for _, a := range aud {
		if a == clientID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("oauth: id_token audience %v does not include %q", aud, clientID)
	}
	exp, err := rc.Expiry.Int64()
	if err != nil {
		return nil, errors.New("oauth: id_token missing/invalid exp")
	}
	expiry := time.Unix(exp, 0)
	if now.After(expiry.Add(skew)) {
		return nil, fmt.Errorf("oauth: id_token expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	if rc.NotBef != "" {
		if nbf, err := rc.NotBef.Int64(); err == nil {
			if now.Add(skew).Before(time.Unix(nbf, 0)) {
				return nil, errors.New("oauth: id_token used before nbf")
			}
		}
	}
	c := &Claims{Issuer: rc.Issuer, Subject: rc.Subject, Audience: aud, Name: rc.Name, JTI: rc.JTI, Expiry: expiry}
	if rc.IssuedAt != "" {
		if iat, err := rc.IssuedAt.Int64(); err == nil {
			c.IssuedAt = time.Unix(iat, 0)
		}
	}
	if c.Subject == "" {
		return nil, errors.New("oauth: id_token missing sub")
	}
	return c, nil
}
