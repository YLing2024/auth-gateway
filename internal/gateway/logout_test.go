package gateway

import (
	"testing"

	"example.com/auth-gateway/internal/config"
	"example.com/auth-gateway/internal/oauth"
)

func newLogoutGateway() *Gateway {
	return &Gateway{
		cfg:      &config.Config{LogoutRedirect: "/"},
		provider: oauth.NewProvider("https://auth.example.com", nil, 0, 0),
	}
}

func TestEndSessionTarget(t *testing.T) {
	app := &appRoute{cfg: config.AppConfig{ID: "appa", Hosts: []string{"a.example.com"}}}
	g := newLogoutGateway()

	// Nothing revoked (no tokens / no session): still hand the browser to the
	// issuer so the SSO session can be ended.
	got, ok := g.endSessionTarget(app, revokeResult{})
	if !ok {
		t.Fatal("expected end_session redirect")
	}
	want := "https://auth.example.com/end_session?client_id=appa&post_logout_redirect_uri=https%3A%2F%2Fa.example.com%2F"
	if got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}

	// Some revocation succeeded: issuer is reachable, keep end_session.
	if _, ok := g.endSessionTarget(app, revokeResult{attempted: 2, succeeded: 1}); !ok {
		t.Fatal("partial success must keep end_session redirect")
	}

	// Every attempt failed: fall back to the local logout page.
	if _, ok := g.endSessionTarget(app, revokeResult{attempted: 2, succeeded: 0}); ok {
		t.Fatal("total revocation failure must fall back locally")
	}

	// No host to build a return URL from: local fallback.
	if _, ok := g.endSessionTarget(&appRoute{cfg: config.AppConfig{ID: "x"}}, revokeResult{}); ok {
		t.Fatal("app without hosts must fall back locally")
	}
}

func TestRevokeAuditResult(t *testing.T) {
	cases := []struct {
		in   revokeResult
		want string
	}{
		{revokeResult{}, "ok"},
		{revokeResult{attempted: 2, succeeded: 2}, "ok"},
		{revokeResult{attempted: 2, succeeded: 1}, "ok:revoke_error"},
		{revokeResult{attempted: 1, succeeded: 0}, "ok:revoke_error"},
	}
	for _, tc := range cases {
		if got := tc.in.auditResult(); got != tc.want {
			t.Fatalf("%+v auditResult = %q, want %q", tc.in, got, tc.want)
		}
	}
}
