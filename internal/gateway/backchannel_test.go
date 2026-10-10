package gateway

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newBackchannelGateway(enabled bool, token string) *Gateway {
	return &Gateway{
		bcEnabled: enabled,
		bcToken:   []byte(token),
		logf:      log.New(io.Discard, "", 0),
	}
}

func TestBackchannelTokenOK(t *testing.T) {
	g := newBackchannelGateway(true, "shared-token")
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"match", "shared-token", true},
		{"wrong", "other-token", false},
		{"empty", "", false},
		{"prefix", "shared", false},
	}
	for _, tc := range cases {
		if got := g.backchannelTokenOK(tc.in); got != tc.want {
			t.Fatalf("%s: backchannelTokenOK(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
	// No configured token: everything fails closed.
	if newBackchannelGateway(true, "").backchannelTokenOK("anything") {
		t.Fatal("unset token must never match")
	}
}

func TestBackchannelEndpointGating(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		method     string
		remoteAddr string
		token      string
		body       string
		want       int
	}{
		{"disabled returns 404", false, http.MethodPost, "127.0.0.1:1234", "shared-token", `{"sid":"s1"}`, http.StatusNotFound},
		{"wrong method", true, http.MethodGet, "127.0.0.1:1234", "shared-token", "", http.StatusMethodNotAllowed},
		{"non-loopback", true, http.MethodPost, "203.0.113.5:1234", "shared-token", `{"sid":"s1"}`, http.StatusUnauthorized},
		{"missing token", true, http.MethodPost, "127.0.0.1:1234", "", `{"sid":"s1"}`, http.StatusUnauthorized},
		{"wrong token", true, http.MethodPost, "127.0.0.1:1234", "nope", `{"sid":"s1"}`, http.StatusUnauthorized},
		{"bad json", true, http.MethodPost, "127.0.0.1:1234", "shared-token", `{`, http.StatusBadRequest},
		{"missing sid", true, http.MethodPost, "127.0.0.1:1234", "shared-token", `{}`, http.StatusBadRequest},
		{"all without sub", true, http.MethodPost, "127.0.0.1:1234", "shared-token", `{"all":true}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newBackchannelGateway(tc.enabled, "shared-token")
			r := httptest.NewRequest(tc.method, "/_auth/backchannel-logout", strings.NewReader(tc.body))
			r.RemoteAddr = tc.remoteAddr
			if tc.token != "" {
				r.Header.Set("X-Internal-Token", tc.token)
			}
			w := httptest.NewRecorder()
			g.handleBackchannelLogout(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:1234":  true,
		"[::1]:1234":      true,
		"203.0.113.5:80":  false,
		"198.51.100.9:80": false,
	}
	for addr, want := range cases {
		if got := isLoopback(addr); got != want {
			t.Fatalf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
