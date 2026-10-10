package oauth

import (
	"net/url"
	"testing"
)

func TestEndSessionURL(t *testing.T) {
	p := NewProvider("https://auth.example.com/", nil, 0, 0)
	got := p.EndSessionURL("appa", "https://a.example.com/")
	want := "https://auth.example.com/end_session?client_id=appa&post_logout_redirect_uri=https%3A%2F%2Fa.example.com%2F"
	if got != want {
		t.Fatalf("EndSessionURL = %q, want %q", got, want)
	}

	// Without a return URL the parameter is omitted (the issuer then renders
	// its own "logged out" page).
	plain := p.EndSessionURL("appa", "")
	u, err := url.Parse(plain)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Path != "/end_session" || u.Query().Get("client_id") != "appa" {
		t.Fatalf("unexpected URL %q", plain)
	}
	if _, ok := u.Query()["post_logout_redirect_uri"]; ok {
		t.Fatalf("post_logout_redirect_uri must be omitted when empty: %q", plain)
	}
}
