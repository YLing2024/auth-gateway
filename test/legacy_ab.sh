#!/usr/bin/env bash
# Legacy A/B regression for the client-bearer change (BRIEF item 9).
#
# Builds two gateways from an OLD config that uses none of the new fields:
#   legacy = the pre-change commit (default 9ef59dd, override with LEGACY_REF)
#   new    = the current working tree
# Both run sequentially on the SAME loopback port with the SAME old-style config
# and a fixed request sequence. The normalized transcripts must be identical.
#
# Uses ports 18933/18936/18937 (within the allowed 18930-18949 range) and Redis
# DB 2 with the private prefix gw:ab:. Requires: go, curl, redis-cli, git, ss.
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEGACY_REF="${LEGACY_REF:-9ef59dd}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/authgw-ab.XXXXXX")"

GW_ADDR="127.0.0.1:18933"
SSO_ADDR="127.0.0.1:18936"
UP_ADDR="127.0.0.1:18937"
GW_PORT="${GW_ADDR##*:}"
HOST_A="a.example.com:${GW_PORT}"
HOST_V2="v2.example.com:${GW_PORT}"
HOST_R="r.example.com:${GW_PORT}"
PREFIX="gw:ab:"

GW_PID=""
SSO_PID=""
UP_PID=""

cleanup() {
  for pid in "$GW_PID" "$SSO_PID" "$UP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 0.2
  redis-cli -n 2 --scan --pattern "${PREFIX}*" 2>/dev/null | while read -r k; do
    redis-cli -n 2 del "$k" >/dev/null 2>&1
  done
  [ "${KEEP_TMP:-0}" = "1" ] && echo "artifacts kept in $TMP" || rm -rf "$TMP"
}
trap cleanup EXIT

die() { echo "FATAL: $*" >&2; exit 2; }

# ── environment ──────────────────────────────────────────────────────────

command -v git >/dev/null || die "git missing"
redis-cli -n 2 ping >/dev/null 2>&1 || die "Redis DB 2 not reachable"

note() { printf '[ab] %s\n' "$1"; }

# ── build legacy (git archive, no worktree metadata touched) ─────────────

mkdir -p "$TMP/legacy"
git -C "$ROOT" archive "$LEGACY_REF" | tar -x -C "$TMP/legacy" || die "cannot extract $LEGACY_REF"
note "legacy source: $LEGACY_REF ($(git -C "$ROOT" rev-parse --short "$LEGACY_REF" 2>/dev/null || echo '?'))"

mkdir -p "$TMP/bin"
( cd "$TMP/legacy" && go build -o "$TMP/bin/legacy-gateway" ./cmd/auth-gateway ) || die "legacy build failed"
( cd "$ROOT" && go build -o "$TMP/bin/new-gateway" ./cmd/auth-gateway ) || die "new build failed"
( cd "$ROOT" && go build -o "$TMP/bin/mocksso" ./cmd/mocksso && \
  go build -o "$TMP/bin/echoupstream" ./cmd/echoupstream ) || die "helper build failed"
note "binaries built"

RAND_HEX="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s' "$RAND_HEX" > "$TMP/token.key"
printf '%s' "$RAND_HEX" > "$TMP/sso.secret"
for app in appa appv2 appr; do printf '%s' "$RAND_HEX" > "$TMP/$app.secret"; done
chmod 600 "$TMP"/*.key "$TMP"/*.secret

# Old-style config: deliberately no accept_bearer / bearer_audiences.
cat > "$TMP/config.yaml" <<EOF
listen: ${GW_ADDR}
issuer: http://${SSO_ADDR}
logout_redirect: "/"
redis:
  addr: 127.0.0.1:6379
  db: 2
  prefix: "${PREFIX}"
session:
  state_ttl_minutes: 10
  ttl_hours: 168
  cookie_suffix: "_session"
token:
  encryption_key_file: ${TMP}/token.key
  jwks_cache_hours: 24
  clock_skew_minutes: 2
audit:
  file: ${TMP}/audit.log
apps:
  - id: appa
    hosts: [a.example.com]
    upstream: http://${UP_ADDR}
    mode: protect
    secret_file: ${TMP}/appa.secret
  - id: appv2
    hosts: [v2.example.com]
    upstream: http://${UP_ADDR}
    api_upstream: http://${UP_ADDR}
    mode: proxy
    secret_file: ${TMP}/appv2.secret
  - id: appr
    hosts: [r.example.com]
    mode: protect
    secret_file: ${TMP}/appr.secret
    routes:
      - prefix: /api/
        upstream: http://${UP_ADDR}
        auth: required
      - prefix: /
        upstream: http://${UP_ADDR}
        auth: none
EOF

header_value() { grep -i "^$2:" "$1" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
cookie_header(){ grep -i '^Set-Cookie:' "$1" | tr -d '\r'; }

# Normalize everything random: session ids, state, PKCE challenge, code and
# proxy-mode access/refresh tokens. Output must be byte-identical across runs.
norm() {
  sed -E \
    -e 's/__Host-[A-Za-z0-9]+_session=[^;[:space:]]+/__Host-APP_session=<TOKEN>/g' \
    -e 's/(code_challenge=)[^&[:space:]]+/\1<CH>/g' \
    -e 's/([?&]code=)[^&[:space:]]+/\1<CODE>/g' \
    -e 's/([?&]state=)[^&[:space:]]+/\1<STATE>/g' \
    -e 's/at-[0-9a-f]+/at-<TOK>/g' \
    -e 's/rt-[0-9a-f]+/rt-<TOK>/g' \
    -e 's/[0-9a-f]{16,}/<HEX>/g' \
    -e 's/^Date:.*/Date: <DATE>/I'
}

N=0
emit() { # label header-file body-file...
  local label="$1" hdr="$2" body="${3:-/dev/null}"
  N=$((N + 1))
  {
    echo "### ${N} ${label}"
    norm < "$hdr"
    echo "--body--"
    if [ -f "$body" ] && [ "$body" != "/dev/null" ]; then norm < "$body"; else echo "(none)"; fi
  } >> "$TR"
}

req() { # label extra-curl-args...
  local label="$1"; shift
  local hdr="$TMP/h.hdr" body="$TMP/h.body"
  curl -sS -o "$body" -D "$hdr" "$@"
  emit "$label" "$hdr" "$body"
}

login_and_emit() { # app cookiehost
  local app="$1" host="$2"
  local h1="$TMP/${app}.1.hdr" h2="$TMP/${app}.2.hdr" h3="$TMP/${app}.3.hdr"
  curl -sS -o /dev/null -D "$h1" -H "Host: ${host}" "http://${GW_ADDR}/_auth/login?next=%2Fdash"
  emit "login-start ${app}" "$h1"
  local auth; auth="$(header_value "$h1" Location)"
  curl -sS -o /dev/null -D "$h2" "$auth"
  emit "authorize ${app}" "$h2"
  local cb; cb="$(header_value "$h2" Location)"
  curl -sS --resolve "${host%:*}:${GW_PORT}:127.0.0.1" -o /dev/null -D "$h3" "$cb"
  emit "callback ${app}" "$h3"
  LOGIN_SID="$(cookie_header "$h3" | sed -n "s/.*__Host-${app}_session=\([^;]*\).*/\1/p")"
}

run_sequence() { # transcript-file
  TR="$1"; N=0
  : > "$TR"
  req "unauth navigation" -H "Host: $HOST_A" "http://${GW_ADDR}/deep/page?x=1"
  req "unauth api" -H "Host: $HOST_A" -H 'Accept: application/json' "http://${GW_ADDR}/api/thing"

  local sid; login_and_emit appa "$HOST_A"; sid="$LOGIN_SID"
  req "cookie dash" -H "Host: $HOST_A" -H "Cookie: __Host-appa_session=$sid" "http://${GW_ADDR}/dash"
  req "forged headers" -H "Host: $HOST_A" -H "Cookie: __Host-appa_session=$sid" \
    -H 'X-Auth-User: root' -H 'X-Auth-Email: root@example.com' -H 'X-Real-IP: 203.0.113.7' \
    "http://${GW_ADDR}/dash"

  local vsid; login_and_emit appv2 "$HOST_V2"; vsid="$LOGIN_SID"
  req "proxy bearer inject" -H "Host: $HOST_V2" -H "Cookie: __Host-appv2_session=$vsid" \
    -H 'Accept: application/json' "http://${GW_ADDR}/api/data"

  req "routes required unauth" -H "Host: $HOST_R" "http://${GW_ADDR}/api/xyz"
  req "routes none public" -H "Host: $HOST_R" "http://${GW_ADDR}/"
  req "auth me unauth" -H "Host: $HOST_A" -H 'Accept: application/json' "http://${GW_ADDR}/_auth/me"
  req "unknown host" -H 'Host: evil.example.com' "http://${GW_ADDR}/"
}

# ── shared mock services ─────────────────────────────────────────────────

"$TMP/bin/mocksso" -addr "$SSO_ADDR" -issuer "http://$SSO_ADDR" -secret-file "$TMP/sso.secret" >"$TMP/mocksso.log" 2>&1 &
SSO_PID=$!
"$TMP/bin/echoupstream" -addr "$UP_ADDR" >"$TMP/upstream.log" 2>&1 &
UP_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://$SSO_ADDR/-/health" >/dev/null 2>&1 && curl -fsS "http://$UP_ADDR/" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://$SSO_ADDR/-/health" >/dev/null 2>&1 || die "mocksso not ready"
curl -fsS "http://$UP_ADDR/" >/dev/null 2>&1 || die "upstream not ready"

run_one() { # label binary prefix-out
  local label="$1" bin="$2" out="$3"
  redis-cli -n 2 --scan --pattern "${PREFIX}*" 2>/dev/null | while read -r k; do
    redis-cli -n 2 del "$k" >/dev/null 2>&1
  done
  GW_PID=""
  "$bin" -config "$TMP/config.yaml" >"$TMP/${label}.gateway.log" 2>&1 &
  GW_PID=$!
  local ready=0
  for _ in $(seq 1 50); do
    if curl -fsS "http://${GW_ADDR}/-/health" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.1
  done
  if [ "$ready" != "1" ]; then
    echo "--- ${label} gateway.log ---"; cat "$TMP/${label}.gateway.log"
    die "${label} gateway not ready"
  fi
  run_sequence "$out"
  kill "$GW_PID" 2>/dev/null; wait "$GW_PID" 2>/dev/null
  GW_PID=""
  sleep 0.3
}

run_one legacy "$TMP/bin/legacy-gateway" "$TMP/legacy.transcript"
run_one new    "$TMP/bin/new-gateway"    "$TMP/new.transcript"

echo
if diff -u "$TMP/legacy.transcript" "$TMP/new.transcript"; then
  echo "A/B legacy vs new: IDENTICAL ($(wc -l < "$TMP/new.transcript" | tr -d ' ') lines, ref $LEGACY_REF)"
  exit 0
fi
echo "A/B legacy vs new: DIFFERENCES FOUND" >&2
exit 1
