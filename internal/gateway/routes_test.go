package gateway

import (
	"testing"

	"example.com/auth-gateway/internal/config"
)

func TestMatchRouteLongestPrefixWins(t *testing.T) {
	routes := []*pathRoute{
		{prefix: "/", auth: config.AuthNone},
		{prefix: "/api/", auth: config.AuthRequired},
	}
	cases := []struct {
		path string
		want string
	}{
		{"/api/x", "/api/"},
		{"/api/", "/api/"},
		{"/", "/"},
		{"/apix", "/"},  // no slash boundary, only "/" matches
		{"/other", "/"}, // falls back to the short public route
	}
	for _, tc := range cases {
		got := matchRoute(routes, tc.path)
		if got == nil {
			t.Fatalf("%s: no match", tc.path)
		}
		if got.prefix != tc.want {
			t.Fatalf("%s: matched %q, want %q", tc.path, got.prefix, tc.want)
		}
	}
}

func TestMatchRouteTieGoesToConfigOrder(t *testing.T) {
	// Equal-length prefixes: the first configured entry wins.
	routes := []*pathRoute{
		{prefix: "/api/a", auth: config.AuthRequired},
		{prefix: "/api/b", auth: config.AuthNone},
	}
	// Neither is a prefix of the other, so the specific match is unambiguous.
	if got := matchRoute(routes, "/api/a/x"); got.prefix != "/api/a" {
		t.Fatalf("matched %q, want /api/a", got.prefix)
	}
}

func TestMatchRouteNoMatch(t *testing.T) {
	routes := []*pathRoute{{prefix: "/api/", auth: config.AuthRequired}}
	if got := matchRoute(routes, "/public"); got != nil {
		t.Fatalf("expected no match, got %q", got.prefix)
	}
}

func TestNewCompilesRoutesWithoutUpstream(t *testing.T) {
	cfg := &config.Config{
		Apps: []config.AppConfig{{
			ID:         "quotahub",
			Hosts:      []string{"quotahub.example.com"},
			Mode:       config.ModeProtect,
			SecretFile: "/unused",
			Routes: []config.Route{
				{Prefix: "/api/", Upstream: "http://127.0.0.1:5300", Auth: config.AuthRequired},
				{Prefix: "/", Upstream: "http://127.0.0.1:5300", Auth: config.AuthNone},
			},
		}},
	}
	g, err := New(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ar := g.byHost["quotahub.example.com"]
	if ar == nil {
		t.Fatal("host not registered")
	}
	if ar.proxy != nil {
		t.Fatal("routes app must not build a legacy whole-site proxy")
	}
	if len(ar.routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(ar.routes))
	}
}
