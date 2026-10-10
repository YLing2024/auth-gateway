[English](README.en.md) | [简体中文](README.md)

# auth-gateway

A single-binary Go SSO authentication gateway: it terminates the gateway session cookie, completes login through OIDC + PKCE, then reverse-proxies the request to a local whitelisted upstream and injects the identity as a request header.

The only dependency is `gopkg.in/yaml.v3`; everything else uses the standard library: a hand-written RESP client for Redis, and `crypto/ecdsa` for JWKS signature verification.

## Build and run

```sh
go build -o bin/auth-gateway ./cmd/auth-gateway
cp config.example.yaml config.yaml   # fill in for the deployment environment
./bin/auth-gateway -config config.yaml
```

When configuration is missing or a key file does not exist the process exits with an error, never degrading to cleartext or a dangerous default.
`listen` accepts only loopback addresses; the gateway is reverse-proxied by nginx and is not directly public.

## Environment variables

Environment variables override the corresponding items in YAML; defaults come from the code:

| Name | Default | Description |
|---|---|---|
| `GATEWAY_CONFIG` | `config.yaml` | configuration file path |
| `GATEWAY_LISTEN` | none (`listen` required) | override `listen` |
| `GATEWAY_ISSUER` | none (`issuer` required) | override `issuer` |
| `GATEWAY_REDIS_ADDR` | none (`redis.addr` required) | override `redis.addr` |
| `GATEWAY_REDIS_DB` | `2` | override `redis.db`, range 0..15 |

See `config.example.yaml` for examples of the remaining keys (`session`, `token`, `audit`, `apps`).

## Key behaviors

- Routes: `/-/health`, `/_auth/{login,callback,logout,me}`; `/_auth/*` precedes the session check.
- Path dispatch (optional `routes`): one app can declare multiple `prefix` entries, longest prefix first (ties in written order); `auth: required` keeps the whole-site auth behavior, and `auth: none` is a public path (no session created, no identity header injected, but client-forged identity headers and gateway cookies are still stripped); no matching prefix returns 404. An app without `routes` behaves unchanged.
- Session cookie: `__Host-<app>_session`, `HttpOnly; Secure; SameSite=Lax; Path=/`, no Domain.
- Not logged in: navigation requests are 302'd to `/_auth/login?next=…`; API requests (JSON/XHR/cors) receive a 401 JSON and the cookie is cleared.
- Reverse proxy: forwards only to the configured whitelist; client identity headers are removed before `X-Auth-User/App/Sid` are injected; the gateway's own cookie is stripped before forwarding; WebSocket and streaming large files are supported; `proxy` mode injects a Bearer token.
- Redis: DB defaults to 2 with keys prefixed `gw:`; `state` is consumed once with a 10-minute TTL; sessions slide for 7 days.
- Token: encrypted with AES-256-GCM and stored in Redis; the key is read from `token.encryption_key_file` (placed with 0600 at deployment).
- Audit: `audit.file` is required; login / logout / denial / refresh events are appended, without recording token or cookie values.
- Logout: clears the local session cookie and Redis record, then best-effort revokes each refresh / access token present in the session (independent of `mode`, with a 3s cap); it then 302s to the auth centre's `<issuer>/end_session` so the browser ends the SSO session (`client_id` plus an absolute `post_logout_redirect_uri` built from the configured `hosts[0]`, never reflected from the request Host). If the auth centre is unreachable / refusing, or no return URL can be built from configuration, it falls back to the local `logout_redirect`; logout never hangs, never 500s and never shows a blank page. The return scheme defaults to `https`; local development may override it with an app-level `scheme: http`.

## Two identity channels: web cookie / native APP Bearer

The same protected route supports both callers, and both map identity to the same upstream header `X-Auth-User` (value `sub`):

- **Web**: after OIDC + PKCE login the gateway sets the session cookie `__Host-<app>_session`, and subsequent requests authenticate by cookie.
- **Native APP / CLI**: cannot share the browser cookie store, so it uses PKCE + system secure storage and carries `Authorization: Bearer <access_token>`. Enabled per app with `accept_bearer: true` (default `false`).
  - Local signature verification, no per-request introspection: verify ES256 with the `/jwks.json` public keys, checking `iss`, `aud`, `exp`/`nbf` (including `clock_skew_minutes`) and `jti` revocation; `alg` must be ES256, rejecting `none`/`HS*`.
  - On success only the identity header is injected, **no cookie is created, changed or cleared**; failure is always `401 JSON` (no 302, since an APP is not a browser).
  - `bearer_audiences` defaults to `[<app.id>]`, and an empty array is a fatal startup error (never degrading to accepting any aud).
  - When a cookie and a Bearer token are both present, the **cookie wins**, so browser behavior is unchanged.
- Note: "accepting a client Bearer" here and `mode: proxy` "injecting a Bearer upstream" (using the access_token saved in the session) are two different things with independent switches; do not mix them.
- A public `auth: none` route does not inject an identity header, and even a valid Bearer is not authenticated; `/_auth/*` behavior is unchanged.

## Offline self-test

`test/selftest.sh` runs the full acceptance on loopback with private ports 18930/18931/18932 and Redis DB 2 (prefix `gw:selftest:`), without real SSO; the ports can be overridden with `SELFTEST_GW_ADDR` / `SELFTEST_SSO_ADDR` / `SELFTEST_UP_ADDR` / `SELFTEST_BAD_PORT`:

```sh
bash test/selftest.sh
bash test/private_scan.sh   # repo private-info scan, expect 0 hits
bash test/legacy_ab.sh      # old-config A/B: before the change (9ef59dd) vs current; normalized output must be identical
go test ./...
```

`cmd/mocksso` and `cmd/echoupstream` are mock services for the self-test, and `test/wsprobe` is a raw WebSocket probe; none are deployable.

## Deployment

The build output is the single binary `bin/auth-gateway`. The repo contains no systemd unit; the process binds only to a loopback address, and nginx terminates TLS and reverse-proxies to `listen`. At runtime it needs to reach `issuer` (OIDC endpoints) and `redis.addr`.
The config file, `*.secret` and `token.key` are not committed (see `.gitignore`).

## License

MIT, see `LICENSE`.
