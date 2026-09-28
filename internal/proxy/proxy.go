// Package proxy is the reverse proxy in front of each protected site.
//
// It never derives the upstream from the incoming request: the target is fixed
// at construction from the configuration whitelist. Client-supplied identity
// headers are removed before the gateway's own values are injected, and the
// gateway's session cookie is stripped so upstreams never see it. WebSocket
// upgrades and large streaming bodies pass through without whole-body buffering
// (httputil.ReverseProxy streams and handles upgrades).
package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"example.com/auth-gateway/internal/config"
	"example.com/auth-gateway/internal/session"
)

// Identity is what the gateway asserts to the upstream.
type Identity struct {
	Sub         string
	App         string
	SID         string
	AccessToken string
}

type ctxKey int

const identityKey ctxKey = 1

// WithIdentity stores the identity on the request context.
func WithIdentity(r *http.Request, id Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey, id))
}

// IdentityFrom returns the identity placed by WithIdentity.
func IdentityFrom(r *http.Request) (Identity, bool) {
	id, ok := r.Context().Value(identityKey).(Identity)
	return id, ok
}

// Handler proxies one configured app.
type Handler struct {
	app         config.AppConfig
	upstream    *httputil.ReverseProxy
	apiUpstream *httputil.ReverseProxy
	suffix      string
}

// New builds a handler bound to the configured upstream(s).
func New(app config.AppConfig, cookieSuffix string) (*Handler, error) {
	h := &Handler{app: app, suffix: cookieSuffix}
	up, err := url.Parse(app.Upstream)
	if err != nil {
		return nil, err
	}
	h.upstream = h.newProxy(up, false)

	if app.Mode == config.ModeProxy {
		apiRaw := app.APIUpstream
		if apiRaw == "" {
			apiRaw = app.Upstream
		}
		au, err := url.Parse(apiRaw)
		if err != nil {
			return nil, err
		}
		h.apiUpstream = h.newProxy(au, true)
	}
	return h, nil
}

// CookieName is the gateway cookie name for this app.
func (h *Handler) CookieName() string { return "__Host-" + h.app.ID + h.suffix }

// App returns the app id.
func (h *Handler) App() string { return h.app.ID }

func (h *Handler) newProxy(target *url.URL, injectBearer bool) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		// -1 flushes every write: SSE and chunked streams reach the client
		// immediately instead of being buffered.
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()

			// 1) Strip every client-supplied identity header first.
			stripIdentityHeaders(pr.Out.Header)
			// 2) Strip the gateway's own session cookies.
			if ck := pr.Out.Header.Get("Cookie"); ck != "" {
				pr.Out.Header.Set("Cookie", session.StripGatewayCookies(ck, h.suffix))
			}
			// 3) Inject the gateway's asserted identity.
			if id, ok := IdentityFrom(pr.In); ok {
				pr.Out.Header.Set("X-Auth-User", id.Sub)
				pr.Out.Header.Set("X-Auth-App", id.App)
				pr.Out.Header.Set("X-Auth-Sid", id.SID)
				if injectBearer && id.AccessToken != "" {
					pr.Out.Header.Set("Authorization", "Bearer "+id.AccessToken)
				}
			}
			// Host must follow the configured upstream, never the request.
			pr.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream_unavailable"}`))
		},
	}
	return rp
}

// ServeHTTP proxies the request to the configured target. isAPI selects the
// api_upstream (and, in proxy mode, the bearer token) when applicable.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.apiUpstream != nil && IsAPIRequest(r) {
		h.apiUpstream.ServeHTTP(w, r)
		return
	}
	h.upstream.ServeHTTP(w, r)
}

// IsAPIRequest reports whether the request should get a JSON 401 instead of a
// redirect when unauthenticated.
func IsAPIRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "cors") {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		return true
	}
	return false
}

// identityHeaders are removed before the gateway sets its own values. This
// closes the header-spoofing hole (a client sending X-Auth-User: root).
var identityHeaders = []string{
	"X-Auth-User",
	"X-Auth-Email",
	"X-Auth-App",
	"X-Auth-Sid",
	"X-Forwarded-User",
	"X-Real-Ip",
}

func stripIdentityHeaders(h http.Header) {
	for _, name := range identityHeaders {
		h.Del(name)
	}
}
