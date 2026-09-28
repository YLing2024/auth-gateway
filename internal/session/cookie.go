package session

import (
	"net/http"
	"strings"
	"time"
)

func unixEpoch() time.Time { return time.Unix(0, 0).UTC() }

// CookieName builds the per-app session cookie name, e.g.
// "__Host-android_session". The __Host- prefix forces Secure + Path=/ + no
// Domain, which browsers enforce.
func CookieName(app, suffix string) string {
	return "__Host-" + app + suffix
}

// SetSessionCookie writes the session cookie. Attribute order mirrors the spec:
// HttpOnly; Secure; SameSite=Lax; Path=/ and no Domain.
func SetSessionCookie(w http.ResponseWriter, name, sid string, maxAgeSeconds int) {
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 604800
	}
	c := &http.Cookie{
		Name:     name,
		Value:    sid,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// ClearSessionCookie expires the session cookie immediately.
func ClearSessionCookie(w http.ResponseWriter, name string) {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  unixEpoch(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

// ReadSessionCookie returns the cookie value, or "" when absent.
func ReadSessionCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// StripGatewayCookies removes the gateway's own session cookies from a Cookie
// header value so upstreams never see them. Other cookies are preserved.
func StripGatewayCookies(header, suffix string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ";")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			name = p[:i]
		}
		if strings.HasPrefix(name, "__Host-") && strings.HasSuffix(name, suffix) {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "; ")
}
