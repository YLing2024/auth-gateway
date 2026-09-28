// Command auth-gateway is a single-binary SSO gateway: it terminates the
// gateway session cookie, obtains an OIDC session via PKCE, and reverse-proxies
// to locally whitelisted upstreams with the identity injected as headers.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/auth-gateway/internal/audit"
	"example.com/auth-gateway/internal/config"
	"example.com/auth-gateway/internal/gateway"
	"example.com/auth-gateway/internal/oauth"
	"example.com/auth-gateway/internal/session"
)

func main() {
	cfgPath := flag.String("config", envOr(config.EnvConfig, "config.yaml"), "path to YAML config")
	flag.Parse()

	logger := log.New(os.Stderr, "auth-gateway ", log.LstdFlags|log.LUTC)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	rdb := session.NewRedis(cfg.Redis.Addr, cfg.Redis.Password, *cfg.Redis.DB, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pingWithRetry(ctx, rdb, logger); err != nil {
		logger.Fatalf("redis: %v", err)
	}

	var crypt *session.Crypt
	if key := cfg.TokenKey(); len(key) > 0 {
		crypt, err = session.NewCrypt(key)
		if err != nil {
			logger.Fatalf("token encryption: %v", err)
		}
	}
	store := session.NewStore(rdb, cfg.Redis.Prefix, crypt,
		time.Duration(cfg.Session.TTLHours)*time.Hour, cfg.Session.CookieSuffix)

	provider := oauth.NewProvider(cfg.Issuer, store,
		time.Duration(cfg.Token.JWKSCacheHours)*time.Hour,
		time.Duration(cfg.Token.ClockSkewMinutes)*time.Minute)

	al, err := audit.Open(cfg.Audit.File)
	if err != nil {
		logger.Fatalf("audit: %v", err)
	}
	defer al.Close()

	gw, err := gateway.New(cfg, store, provider, al, logger)
	if err != nil {
		logger.Fatalf("gateway: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: WebSocket tunnels and large streams must run long.
		IdleTimeout: 120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (issuer %s, redis db %d)", cfg.Listen, cfg.Issuer, *cfg.Redis.DB)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Fatalf("serve: %v", err)
	case sig := <-sigCh:
		logger.Printf("received %s, shutting down", sig)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
}

func pingWithRetry(ctx context.Context, rdb *session.Redis, logger *log.Logger) error {
	var last error
	for i := 0; i < 5; i++ {
		if last = rdb.Ping(); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(300 * time.Millisecond):
		}
	}
	return last
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
