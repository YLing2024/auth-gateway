package gateway

import (
	"net/http"
	"testing"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		token   string
		present bool
	}{
		{"absent", "", "", false},
		{"valid", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"scheme case-insensitive", "bearer tok", "tok", true},
		{"extra spaces", "  Bearer   tok  ", "tok", true},
		{"empty token still counts", "Bearer", "", true},
		{"other scheme ignored", "Basic dXNlcjpwYXNz", "", false},
		{"bare token ignored", "abc.def.ghi", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			tok, present := bearerToken(r)
			if tok != tc.token || present != tc.present {
				t.Fatalf("bearerToken(%q) = (%q, %v), want (%q, %v)", tc.header, tok, present, tc.token, tc.present)
			}
		})
	}
}
