// Package gateway wires configuration, Redis state, the OAuth provider and the
// reverse proxy into one HTTP handler.
//
// Routing order is deliberate: /_auth/* is matched before any session check,
// otherwise an unauthenticated /_auth/login would itself redirect to
// /_auth/login and loop.
package gateway

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/auth-gateway/internal/audit"
	"example.com/auth-gateway/internal/config"
	"example.com/auth-gateway/internal/oauth"
	"example.com/auth-gateway/internal/proxy"
	"example.com/auth-gateway/internal/session"
)

// Gateway is the assembled handler.
type Gateway struct {
	cfg      *config.Config
	provider *oauth.Provider
	store    *session.Store
	audit    *audit.Logger
	apps     []*appRoute
	byHost   map[string]*appRoute
	stateTTL time.Duration
	sessTTL  time.Duration
	logf     *log.Logger
}

type appRoute struct {
	cfg        config.AppConfig
	proxy      *proxy.Handler // legacy whole-site handler (nil when routes exist)
	cookieName string
	routes     []*pathRoute // non-empty only for path-routed apps
}

// pathRoute is one compiled route entry. Matching is longest-prefix-first; the
// slice is kept in config order so equal-length prefixes resolve to the first.
type pathRoute struct {
	prefix string
	auth   string
	proxy  *proxy.Handler
}

// matchRoute returns the route with the longest matching prefix, or nil.
func matchRoute(routes []*pathRoute, path string) *pathRoute {
	var best *pathRoute
	bestLen := -1
	for _, rt := range routes {
		if len(rt.prefix) > bestLen && strings.HasPrefix(path, rt.prefix) {
			best = rt
			bestLen = len(rt.prefix)
		}
	}
	return best
}

// New assembles the gateway from validated configuration and shared services.
func New(cfg *config.Config, store *session.Store, provider *oauth.Provider, al *audit.Logger, logger *log.Logger) (*Gateway, error) {
	if logger == nil {
		logger = log.Default()
	}
	g := &Gateway{
		cfg:      cfg,
		provider: provider,
		store:    store,
		audit:    al,
		byHost:   make(map[string]*appRoute),
		stateTTL: time.Duration(cfg.Session.StateTTLMinutes) * time.Minute,
		sessTTL:  time.Duration(cfg.Session.TTLHours) * time.Hour,
		logf:     logger,
	}
	for _, ac := range cfg.Apps {
		ar := &appRoute{cfg: ac, cookieName: session.CookieName(ac.ID, cfg.Session.CookieSuffix)}
		if len(ac.Routes) == 0 {
			p, err := proxy.New(ac, cfg.Session.CookieSuffix)
			if err != nil {
				return nil, err
			}
			ar.proxy = p
		} else {
			for _, rt := range ac.Routes {
				injectBearer := rt.Auth == config.AuthRequired && ac.Mode == config.ModeProxy
				p, err := proxy.NewForRoute(ac.ID, rt.Upstream, cfg.Session.CookieSuffix, injectBearer)
				if err != nil {
					return nil, err
				}
				ar.routes = append(ar.routes, &pathRoute{prefix: rt.Prefix, auth: rt.Auth, proxy: p})
			}
		}
		g.apps = append(g.apps, ar)
		for _, h := range ac.Hosts {
			g.byHost[strings.ToLower(strings.TrimSpace(h))] = ar
		}
	}
	return g, nil
}

// Handler returns the root mux.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/health", g.handleHealth)
	mux.HandleFunc("/_auth/login", g.handleLogin)
	mux.HandleFunc("/_auth/callback", g.handleCallback)
	mux.HandleFunc("/_auth/logout", g.handleLogout)
	mux.HandleFunc("/_auth/me", g.handleMe)
	// Everything else under /_auth/ is cargo-cult noise: 404, do not proxy.
	mux.HandleFunc("/_auth/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

// ── health ───────────────────────────────────────────────────────────────

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── login ────────────────────────────────────────────────────────────────

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	app := g.appForRequest(r)
	if app == nil {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	pkce, err := oauth.NewPKCE()
	if err != nil {
		g.fail(w, "login", err)
		return
	}
	state, err := oauth.RandomState()
	if err != nil {
		g.fail(w, "login", err)
		return
	}
	original := g.resolveOriginal(r, r.URL.Query().Get("next"))
	st := session.State{App: app.cfg.ID, Verifier: pkce.Verifier, OriginalURL: original, CreatedAt: time.Now().Unix()}
	if err := g.store.PutState(state, st, g.stateTTL); err != nil {
		g.fail(w, "login", err)
		return
	}
	authURL := g.provider.AuthorizeURL(app.cfg.ID, g.redirectURI(r), state, pkce.Challenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ── callback ─────────────────────────────────────────────────────────────

func (g *Gateway) handleCallback(w http.ResponseWriter, r *http.Request) {
	app := g.appForRequest(r)
	if app == nil {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "authorization failed: "+e, http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}
	st, ok, err := g.store.TakeState(state) // atomic one-time consume
	if err != nil {
		g.fail(w, "callback", err)
		return
	}
	if !ok || st.App != app.cfg.ID {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	tr, err := g.provider.ExchangeCode(r.Context(), app.cfg.ID, app.cfg.ClientSecret, code, g.redirectURI(r), st.Verifier)
	if err != nil {
		g.audit.Log(app.cfg.ID, "", "login", "error:token_exchange")
		g.fail(w, "callback", err)
		return
	}
	claims, err := g.provider.VerifyIDToken(r.Context(), tr.IDToken, app.cfg.ID)
	if err != nil {
		g.audit.Log(app.cfg.ID, "", "login", "error:id_token")
		g.fail(w, "callback", err)
		return
	}
	sid, err := oauth.RandomSID()
	if err != nil {
		g.fail(w, "callback", err)
		return
	}
	sess := session.Session{
		App:         app.cfg.ID,
		Sub:         claims.Subject,
		Name:        claims.Name,
		Exp:         claims.Expiry.Unix(),
		OriginalURL: st.OriginalURL,
	}
	if app.cfg.Mode == config.ModeProxy {
		sess.AccessToken = tr.AccessToken
		sess.RefreshToken = tr.RefreshToken
		if !tr.Expiry.IsZero() {
			sess.Exp = tr.Expiry.Unix()
		}
	}
	if err := g.store.PutSession(sid, sess, g.sessTTL); err != nil {
		g.fail(w, "callback", err)
		return
	}
	session.SetSessionCookie(w, app.cookieName, sid, int(g.sessTTL.Seconds()))
	g.audit.Log(app.cfg.ID, claims.Subject, "login", "ok")
	http.Redirect(w, r, safePath(st.OriginalURL, g.cfg.LogoutRedirect), http.StatusFound)
}

// ── logout ───────────────────────────────────────────────────────────────

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	app := g.appForRequest(r)
	if app == nil {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	sid := session.ReadSessionCookie(r, app.cookieName)
	if sid != "" {
		if sess, ok, err := g.store.GetSession(sid); err == nil && ok {
			if app.cfg.Mode == config.ModeProxy && sess.RefreshToken != "" {
				_ = g.provider.Revoke(r.Context(), app.cfg.ID, app.cfg.ClientSecret, sess.RefreshToken)
			}
			g.audit.Log(app.cfg.ID, sess.Sub, "logout", "ok")
		}
		if err := g.store.DeleteSession(sid); err != nil {
			g.logf.Printf("logout: delete session: %v", err)
		}
	}
	session.ClearSessionCookie(w, app.cookieName)
	http.Redirect(w, r, g.cfg.LogoutRedirect, http.StatusFound)
}

// ── me ───────────────────────────────────────────────────────────────────

func (g *Gateway) handleMe(w http.ResponseWriter, r *http.Request) {
	app := g.appForRequest(r)
	if app == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown_host"})
		return
	}
	sess, ok := g.validSession(r, app)
	if !ok {
		session.ClearSessionCookie(w, app.cookieName)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": sess.Sub, "name": sess.Name, "app": app.cfg.ID})
}

// ── proxy ────────────────────────────────────────────────────────────────

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	app := g.appForRequest(r)
	if app == nil {
		// Unknown host: never forward. The configured whitelist is the only
		// source of upstream targets.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if len(app.routes) == 0 {
		// Legacy whole-site app: unchanged behaviour.
		g.serveProtected(w, r, app, app.proxy)
		return
	}
	rt := matchRoute(app.routes, r.URL.Path)
	if rt == nil {
		// No route claims this path: never fall through to a default target.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if rt.auth == config.AuthNone {
		// Public route: no session is created or read and no identity header is
		// injected. The handler still strips client-forged identity headers and
		// the gateway's own cookie before forwarding.
		rt.proxy.ServeHTTP(w, r)
		return
	}
	g.serveProtected(w, r, app, rt.proxy)
}

// serveProtected runs the existing required-session flow (302/401 split, session
// validation, silent refresh, identity injection) against one proxy handler.
func (g *Gateway) serveProtected(w http.ResponseWriter, r *http.Request, app *appRoute, p *proxy.Handler) {
	sess, ok := g.validSession(r, app)
	if !ok {
		if proxy.IsAPIRequest(r) {
			session.ClearSessionCookie(w, app.cookieName)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			g.audit.Log(app.cfg.ID, "", "denied", "api")
			return
		}
		next := r.URL.RequestURI()
		g.audit.Log(app.cfg.ID, "", "denied", "navigation")
		http.Redirect(w, r, "/_auth/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	id := proxy.Identity{Sub: sess.Sub, App: app.cfg.ID, SID: sess.SID, AccessToken: sess.AccessToken}
	id = g.maybeRefresh(r, app, sess, id)
	p.ServeHTTP(w, proxy.WithIdentity(r, id))
}

// validSession reads and validates the per-app cookie. A session minted for a
// different app is rejected, which keeps apps isolated even if a cookie is
// replayed against the wrong host.
func (g *Gateway) validSession(r *http.Request, app *appRoute) (session.Session, bool) {
	sid := session.ReadSessionCookie(r, app.cookieName)
	if sid == "" {
		return session.Session{}, false
	}
	sess, ok, err := g.store.GetSession(sid)
	if err != nil {
		g.logf.Printf("session: get %s: %v", app.cfg.ID, err)
		return session.Session{}, false
	}
	if !ok || sess.App != app.cfg.ID {
		return session.Session{}, false
	}
	return sess, true
}

// maybeRefresh silently renews an expired access token in proxy mode using the
// stored refresh token. Local validation means we never call introspection on
// the happy path.
func (g *Gateway) maybeRefresh(r *http.Request, app *appRoute, sess session.Session, id proxy.Identity) proxy.Identity {
	if app.cfg.Mode != config.ModeProxy || sess.RefreshToken == "" {
		return id
	}
	if sess.Exp > time.Now().Add(30*time.Second).Unix() {
		return id
	}
	tr, err := g.provider.Refresh(r.Context(), app.cfg.ID, app.cfg.ClientSecret, sess.RefreshToken)
	if err != nil {
		g.audit.Log(app.cfg.ID, sess.Sub, "refresh", "error")
		return id
	}
	sess.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		sess.RefreshToken = tr.RefreshToken
	}
	if !tr.Expiry.IsZero() {
		sess.Exp = tr.Expiry.Unix()
	}
	if err := g.store.PutSession(sess.SID, sess, g.sessTTL); err != nil {
		g.logf.Printf("session: refresh persist: %v", err)
	}
	g.audit.Log(app.cfg.ID, sess.Sub, "refresh", "ok")
	id.AccessToken = tr.AccessToken
	return id
}

// ── helpers ──────────────────────────────────────────────────────────────

func (g *Gateway) appForRequest(r *http.Request) *appRoute {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if i := strings.IndexByte(host, ','); i >= 0 { // first value only
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return g.byHost[strings.ToLower(host)]
}

// redirectURI reconstructs the callback URL. Scheme comes from
// X-Forwarded-Proto when behind nginx, else from the connection.
func (g *Gateway) redirectURI(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + host + "/_auth/callback"
}

// resolveOriginal picks where to send the user after login: the explicit next
// parameter first, then a same-host Referer, else "/".
func (g *Gateway) resolveOriginal(r *http.Request, next string) string {
	if p := safePath(next, ""); p != "" {
		return p
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			if sameHost(u.Host, requestHost(r)) {
				if p := safePath(u.RequestURI(), ""); p != "" {
					return p
				}
			}
		}
	}
	return "/"
}

func requestHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func sameHost(a, b string) bool { return strings.EqualFold(a, b) }

// safePath accepts only a site-absolute path: it must start with a single "/"
// and contain no control characters. This blocks open redirects to other
// origins while still allowing query strings.
func safePath(v, fallback string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return fallback
	}
	if strings.ContainsAny(v, "\r\n\t\\") {
		return fallback
	}
	return v
}

func (g *Gateway) fail(w http.ResponseWriter, action string, err error) {
	g.logf.Printf("%s: %v", action, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
