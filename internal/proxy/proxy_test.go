package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/auth-gateway/internal/config"
)

func TestProxyStripsAndInjectsIdentity(t *testing.T) {
	var got struct {
		User      string
		App       string
		SID       string
		Email     string
		RealIP    string
		Cookie    string
		Forwarded string
		Auth      string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.User = r.Header.Get("X-Auth-User")
		got.App = r.Header.Get("X-Auth-App")
		got.SID = r.Header.Get("X-Auth-Sid")
		got.Email = r.Header.Get("X-Auth-Email")
		got.RealIP = r.Header.Get("X-Real-IP")
		got.Cookie = r.Header.Get("Cookie")
		got.Forwarded = r.Header.Get("X-Forwarded-For")
		got.Auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h, err := New(config.AppConfig{ID: "android", Upstream: upstream.URL, Mode: config.ModeProtect}, "_session")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://android.example.com/dash", nil)
	req.Header.Set("X-Auth-User", "root") // forged
	req.Header.Set("X-Auth-Email", "root@example.com")
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.Header.Set("Cookie", "__Host-android_session=deadbeef; theme=dark")
	req = WithIdentity(req, Identity{Sub: "user-42", App: "android", SID: "sid-1"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got.User != "user-42" {
		t.Fatalf("X-Auth-User = %q, want gateway-injected user-42 (forgery leaked!)", got.User)
	}
	if got.App != "android" || got.SID != "sid-1" {
		t.Fatalf("identity headers wrong: app=%q sid=%q", got.App, got.SID)
	}
	if got.Email != "" || got.RealIP != "" {
		t.Fatalf("forged headers survived: email=%q real-ip=%q", got.Email, got.RealIP)
	}
	if got.Cookie != "theme=dark" {
		t.Fatalf("upstream cookie = %q, want only non-gateway cookies", got.Cookie)
	}
	if got.Forwarded == "" {
		t.Fatal("X-Forwarded-For not set")
	}
	if got.Auth != "" {
		t.Fatalf("protect mode must not inject Authorization, got %q", got.Auth)
	}
}

func TestProxyModeInjectsBearer(t *testing.T) {
	var auth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	h, err := New(config.AppConfig{ID: "v2", Upstream: upstream.URL, APIUpstream: upstream.URL, Mode: config.ModeProxy}, "_session")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://v2.example.com/api/x", nil)
	req.Header.Set("Accept", "application/json")
	req = WithIdentity(req, Identity{Sub: "u", App: "v2", SID: "s", AccessToken: "at-123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if auth != "Bearer at-123" {
		t.Fatalf("Authorization = %q, want Bearer at-123", auth)
	}
}

func TestIsAPIRequest(t *testing.T) {
	cases := []struct {
		method string
		header [2]string
		want   bool
	}{
		{http.MethodGet, [2]string{"Accept", "text/html"}, false},
		{http.MethodGet, [2]string{"Accept", "application/json"}, true},
		{http.MethodGet, [2]string{"X-Requested-With", "XMLHttpRequest"}, true},
		{http.MethodGet, [2]string{"Sec-Fetch-Mode", "cors"}, true},
		{http.MethodPost, [2]string{"", ""}, true},
		{http.MethodGet, [2]string{"", ""}, false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, "http://x.example.com/", nil)
		if tc.header[0] != "" {
			r.Header.Set(tc.header[0], tc.header[1])
		}
		if got := IsAPIRequest(r); got != tc.want {
			t.Fatalf("%s %v: IsAPIRequest = %v, want %v", tc.method, tc.header, got, tc.want)
		}
	}
}

func TestProxyTargetIsWhitelisted(t *testing.T) {
	// A request Host header must never change the target; the handler is bound
	// to the configured upstream only.
	var host string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
	}))
	defer upstream.Close()
	h, _ := New(config.AppConfig{ID: "a", Upstream: upstream.URL, Mode: config.ModeProtect}, "_session")
	req := httptest.NewRequest(http.MethodGet, "http://attacker.example.com/", nil)
	req = WithIdentity(req, Identity{Sub: "u", App: "a", SID: "s"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if host == "attacker.example.com" {
		t.Fatal("request Host leaked to upstream; target must come from config")
	}
}
