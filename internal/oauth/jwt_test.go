package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + enc.EncodeToString(sig)
}

func jwksFor(key *ecdsa.PrivateKey, kid string) []byte {
	pub := key.PublicKey
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

func TestVerifyIDToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"
	doc := jwksFor(key, kid)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	defer srv.Close()

	p := NewProvider(srv.URL, nil, time.Hour, 2*time.Minute)
	good := signES256(t, key, kid, map[string]any{
		"iss": srv.URL, "sub": "user-1", "aud": "android", "name": "Test User",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	if _, err := p.VerifyIDToken(t.Context(), good, "android"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", hits)
	}
	// Second verification must come from cache.
	if _, err := p.VerifyIDToken(t.Context(), good, "android"); err != nil {
		t.Fatalf("cached verification failed: %v", err)
	}
	if hits != 1 {
		t.Fatalf("JWKS refetched for a valid cached key: hits=%d", hits)
	}

	cases := []struct {
		name   string
		claims map[string]any
		app    string
	}{
		{"wrong audience", map[string]any{"iss": srv.URL, "sub": "u", "aud": "other", "exp": time.Now().Add(time.Hour).Unix()}, "android"},
		{"wrong issuer", map[string]any{"iss": "https://evil.example.com", "sub": "u", "aud": "android", "exp": time.Now().Add(time.Hour).Unix()}, "android"},
		{"expired", map[string]any{"iss": srv.URL, "sub": "u", "aud": "android", "exp": time.Now().Add(-time.Hour).Unix()}, "android"},
	}
	for _, tc := range cases {
		tok := signES256(t, key, kid, tc.claims)
		if _, err := p.VerifyIDToken(t.Context(), tok, tc.app); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		}
	}
}

func TestVerifyIDTokenRejectsTamperedSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := jwksFor(other, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	p := NewProvider(srv.URL, nil, time.Hour, 0)
	tok := signES256(t, key, "k1", map[string]any{"iss": srv.URL, "sub": "u", "aud": "a", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := p.VerifyIDToken(t.Context(), tok, "a"); err == nil {
		t.Fatal("token signed by an unknown key was accepted")
	}
}

func TestVerifyAccessToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "acc-key-1"
	doc := jwksFor(key, kid)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	p := NewProvider(srv.URL, nil, time.Hour, 2*time.Minute)

	good := signES256(t, key, kid, map[string]any{
		"iss": srv.URL, "sub": "app-user-9", "aud": []string{"home-admin", "admin"},
		"exp": time.Now().Add(time.Hour).Unix(), "jti": "jti-1",
	})
	claims, err := p.VerifyAccessToken(t.Context(), good, []string{"admin"})
	if err != nil {
		t.Fatalf("valid access token rejected: %v", err)
	}
	if claims.Subject != "app-user-9" || claims.JTI != "jti-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	// Array audience must also match a single accepted value.
	if _, err := p.VerifyAccessToken(t.Context(), good, []string{"nope"}); err == nil {
		t.Fatal("audience outside the list must be rejected")
	}
	// No accepted audiences is a programming error, never "accept all".
	if _, err := p.VerifyAccessToken(t.Context(), good, nil); err == nil {
		t.Fatal("empty accepted audiences must be rejected")
	}

	expired := signES256(t, key, kid, map[string]any{
		"iss": srv.URL, "sub": "u", "aud": "admin", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := p.VerifyAccessToken(t.Context(), expired, []string{"admin"}); err == nil {
		t.Fatal("expired access token must be rejected")
	}

	// alg:none (unsigned) must be rejected before keys are consulted.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	nonePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + srv.URL + `","sub":"u","aud":"admin","exp":` + itoa(time.Now().Add(time.Hour).Unix()) + `}`))
	if _, err := p.VerifyAccessToken(t.Context(), noneHeader+"."+nonePayload+".", []string{"admin"}); err == nil {
		t.Fatal("alg:none token must be rejected")
	}

	// Tampered signature must be rejected.
	tampered := good[:len(good)-2] + "AA"
	if _, err := p.VerifyAccessToken(t.Context(), tampered, []string{"admin"}); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestAuthorizeURL(t *testing.T) {
	p := NewProvider("https://auth.example.com/", nil, time.Hour, 0)
	got := p.AuthorizeURL("android", "https://android.example.com/_auth/callback", "st", "ch")
	want := "https://auth.example.com/authorize?client_id=android&code_challenge=ch&code_challenge_method=S256&redirect_uri=" +
		"https%3A%2F%2Fandroid.example.com%2F_auth%2Fcallback&response_type=code&scope=openid+profile&state=st"
	if got != want {
		t.Fatalf("AuthorizeURL mismatch:\n got %s\nwant %s", got, want)
	}
}
