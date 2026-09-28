// Command mocksso is an offline stand-in for the SSO issuer used by the
// gateway self-test. It implements just enough of the OIDC flow: a JWKS with an
// ephemeral ES256 key, /authorize, /token (PKCE + client_secret validation) and
// /revoke. It must never be deployed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type pending struct {
	clientID    string
	redirectURI string
	challenge   string
	method      string
}

type server struct {
	issuer string
	secret string
	key    *ecdsa.PrivateKey
	kid    string

	mu     sync.Mutex
	codes  map[string]pending
	logger *log.Logger
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18931", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:18931", "issuer base URL included in iss")
	secretFile := flag.String("secret-file", "", "file holding the shared client secret")
	flag.Parse()

	if *secretFile == "" {
		log.Fatal("mocksso: -secret-file is required")
	}
	sb, err := os.ReadFile(*secretFile)
	if err != nil {
		log.Fatalf("mocksso: read secret: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("mocksso: key: %v", err)
	}
	s := &server{
		issuer: strings.TrimRight(*issuer, "/"),
		secret: strings.TrimSpace(string(sb)),
		key:    key,
		kid:    "mock-key-1",
		codes:  map[string]pending{},
		logger: log.New(os.Stderr, "mocksso ", log.LstdFlags),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/-/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })

	s.logger.Printf("listening on %s (issuer %s)", *addr, s.issuer)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("mocksso: %v", err)
	}
}

func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := s.key.PublicKey
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": s.kid, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 required", http.StatusBadRequest)
		return
	}
	code, err := randomHex(24)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.codes[code] = pending{clientID: clientID, redirectURI: redirectURI, challenge: challenge, method: "S256"}
	s.mu.Unlock()

	back, err := appendQuery(redirectURI, map[string]string{"code": code, "state": q.Get("state")})
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, back, http.StatusFound)
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")
	code := r.PostFormValue("code")
	verifier := r.PostFormValue("code_verifier")
	if clientSecret != s.secret {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	p, ok := s.codes[code]
	if ok {
		delete(s.codes, code) // authorization code is single use
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if p.clientID != clientID {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
		http.Error(w, "invalid_grant: pkce mismatch", http.StatusBadRequest)
		return
	}

	now := time.Now()
	idToken, err := s.signIDToken(map[string]any{
		"iss": s.issuer, "sub": "mock-user-1", "aud": clientID, "name": "Mock User",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": mustRandom(8),
	})
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	access := "at-" + mustRandom(16)
	refresh := "rt-" + mustRandom(16)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": access, "refresh_token": refresh, "id_token": idToken,
		"token_type": "Bearer", "expires_in": 3600,
	})
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"revoked":true}`)
}

func (s *server) signIDToken(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": "JWT", "kid": s.kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signingInput))
	rr, ss, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func mustRandom(n int) string {
	v, err := randomHex(n)
	if err != nil {
		panic(err)
	}
	return v
}

func appendQuery(raw string, extra map[string]string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range extra {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
