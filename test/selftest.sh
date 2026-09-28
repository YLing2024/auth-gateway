#!/usr/bin/env bash
# Offline self-test for the auth-gateway (BRIEF section 3).
#
# Everything runs on loopback with private ports 18930/18931/18932 and Redis
# DB 2 using the dedicated prefix gw:selftest:. No real SSO, no production
# ports and no systemd are touched. Requires: go, curl, redis-cli, ss.
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/authgw-selftest.XXXXXX")"

GW_ADDR="127.0.0.1:18930"
SSO_ADDR="127.0.0.1:18931"
UP_ADDR="127.0.0.1:18932"
HOST_A="a.example.com:18930"
HOST_B="b.example.com:18930"
HOST_V2="v2.example.com:18930"
HOST_R="r.example.com:18930"
HOST_NR="nr.example.com:18930"
HOST_BEAR="bear.example.com:18930"
PREFIX="gw:selftest:"

PASS=0
FAIL=0
FAILED_CASES=()

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
  if [ "${KEEP_TMP:-0}" = "1" ]; then
    echo "artifacts kept in $TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

title() { printf '\n===== %s =====\n' "$1"; }
note()  { printf '  [INFO] %s\n' "$1"; }

check_eq() { # desc expected actual
  if [ "$2" = "$3" ]; then
    printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1))
  else
    printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"
    FAIL=$((FAIL + 1)); FAILED_CASES+=("$1")
  fi
}

check_contains() { # desc needle haystack
  if printf '%s' "$3" | grep -qF -- "$2"; then
    printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1))
  else
    printf '  [FAIL] %s\n         needle missing: %s\n' "$1" "$2"
    FAIL=$((FAIL + 1)); FAILED_CASES+=("$1")
  fi
}

check_not_contains() { # desc needle haystack
  if printf '%s' "$3" | grep -qF -- "$2"; then
    printf '  [FAIL] %s\n         forbidden value present: %s\n' "$1" "$2"
    FAIL=$((FAIL + 1)); FAILED_CASES+=("$1")
  else
    printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1))
  fi
}

header_value() { grep -i "^$2:" "$1" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
status_of()    { awk 'NR==1{print $2}' "$1" | tr -d '\r'; }
cookie_header(){ grep -i '^Set-Cookie:' "$1" | tr -d '\r'; }
json_str()     { grep -o "\"$2\":\"[^\"]*\"" "$1" | head -1 | sed 's/.*:"//; s/"$//'; }

# ── 0. environment ───────────────────────────────────────────────────────

title "0) 环境准备（构建 + Redis DB2 可达）"

if ! redis-cli -n 2 ping >/dev/null 2>&1; then
  echo "FATAL: Redis DB 2 not reachable (redis-cli -n 2 ping failed)" >&2
  exit 2
fi
note "redis db2: $(redis-cli -n 2 ping)"

RAND_HEX="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s' "$RAND_HEX" > "$TMP/token.key"
printf '%s' "$RAND_HEX" > "$TMP/sso.secret"
for app in appa appb appv2 appr appnr appbear; do printf '%s' "$RAND_HEX" > "$TMP/$app.secret"; done
chmod 600 "$TMP"/*.key "$TMP"/*.secret

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
  - id: appb
    hosts: [b.example.com]
    upstream: http://${UP_ADDR}
    mode: protect
    secret_file: ${TMP}/appb.secret
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
    accept_bearer: true
    bearer_audiences: [appr, admin]
    routes:
      - prefix: /api/
        upstream: http://${UP_ADDR}
        auth: required
      - prefix: /
        upstream: http://${UP_ADDR}
        auth: none
  - id: appnr
    hosts: [nr.example.com]
    mode: protect
    secret_file: ${TMP}/appnr.secret
    routes:
      - prefix: /api/
        upstream: http://${UP_ADDR}
        auth: required
  - id: appbear
    hosts: [bear.example.com]
    upstream: http://${UP_ADDR}
    mode: protect
    secret_file: ${TMP}/appbear.secret
    accept_bearer: true
    bearer_audiences: [admin, home-admin]
EOF

printf '$ go build -o %s/bin ./cmd/...\n' "$TMP"
mkdir -p "$TMP/bin"
( cd "$ROOT" && go build -o "$TMP/bin/auth-gateway" ./cmd/auth-gateway && \
  go build -o "$TMP/bin/mocksso" ./cmd/mocksso && \
  go build -o "$TMP/bin/echoupstream" ./cmd/echoupstream && \
  go build -o "$TMP/bin/wsprobe" ./test/wsprobe ) || { echo "FATAL: build failed" >&2; exit 2; }
note "binaries: $(ls "$TMP/bin" | tr '\n' ' ')"

"$TMP/bin/mocksso" -addr "$SSO_ADDR" -issuer "http://$SSO_ADDR" -secret-file "$TMP/sso.secret" >"$TMP/mocksso.log" 2>&1 &
SSO_PID=$!
"$TMP/bin/echoupstream" -addr "$UP_ADDR" >"$TMP/upstream.log" 2>&1 &
UP_PID=$!
"$TMP/bin/auth-gateway" -config "$TMP/config.yaml" >"$TMP/gateway.log" 2>&1 &
GW_PID=$!

ready=0
for _ in $(seq 1 50); do
  if curl -fsS "http://$GW_ADDR/-/health" >/dev/null 2>&1 \
     && curl -fsS "http://$SSO_ADDR/-/health" >/dev/null 2>&1 \
     && curl -fsS "http://$UP_ADDR/" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 0.1
done
if [ "$ready" != "1" ]; then
  echo "FATAL: services did not become ready" >&2
  echo "--- gateway.log ---"; cat "$TMP/gateway.log"
  echo "--- mocksso.log ---"; cat "$TMP/mocksso.log"
  echo "--- upstream.log ---"; cat "$TMP/upstream.log"
  exit 2
fi
note "services ready: gateway pid=$GW_PID sso pid=$SSO_PID upstream pid=$UP_PID"

HEALTH="$(curl -sS "http://$GW_ADDR/-/health")"
note "health: $HEALTH"

# ── 1. unauthenticated navigation → 302 ──────────────────────────────────

title "1) 未登录导航请求 → 302 /_auth/login"
printf '$ curl -sS -o /dev/null -D - -H %s http://%s/deep/page?x=1\n' "'Host: a.example.com'" "$GW_ADDR"
curl -sS -o /dev/null -D "$TMP/c1.hdr" -H "Host: $HOST_A" "http://$GW_ADDR/deep/page?x=1"
cat "$TMP/c1.hdr"
check_eq "1.1 状态码 302" "302" "$(status_of "$TMP/c1.hdr")"
check_eq "1.2 Location 指向登录并带 next" \
  "/_auth/login?next=%2Fdeep%2Fpage%3Fx%3D1" "$(header_value "$TMP/c1.hdr" Location)"

# ── 2. unauthenticated API → 401 JSON + clear cookie ─────────────────────

title "2) 未登录 API 请求 → 401 JSON + 清 cookie"
printf '$ curl -sS -D - -o body -H %s -H %s http://%s/api/thing\n' \
  "'Host: a.example.com'" "'Accept: application/json'" "$GW_ADDR"
curl -sS -D "$TMP/c2.hdr" -o "$TMP/c2.body" -H "Host: $HOST_A" -H 'Accept: application/json' "http://$GW_ADDR/api/thing"
cat "$TMP/c2.hdr"; printf -- '--- body ---\n'; cat "$TMP/c2.body"; printf '\n'
C2COOKIE="$(cookie_header "$TMP/c2.hdr")"
check_eq "2.1 状态码 401" "401" "$(status_of "$TMP/c2.hdr")"
check_contains "2.2 body 为 401 JSON" '"error":"unauthenticated"' "$(cat "$TMP/c2.body")"
check_contains "2.3 清 cookie 名字正确" "__Host-appa_session=" "$C2COOKIE"
check_contains "2.4 清 cookie Max-Age=0" "Max-Age=0" "$C2COOKIE"

# ── 3. full login flow ───────────────────────────────────────────────────

title "3) 完整登录流程（login → authorize → token → callback）"
printf '$ curl -sS -o /dev/null -D - -H %s http://%s/_auth/login?next=%%2Fdeep%%2Fpage%%3Fx%%3D1\n' \
  "'Host: a.example.com:18930'" "$GW_ADDR"
curl -sS -o /dev/null -D "$TMP/c3a.hdr" -H "Host: $HOST_A" "http://$GW_ADDR/_auth/login?next=%2Fdeep%2Fpage%3Fx%3D1"
cat "$TMP/c3a.hdr"
AUTH_URL="$(header_value "$TMP/c3a.hdr" Location)"
STATE_A="$(printf '%s' "$AUTH_URL" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')"
check_eq "3.1 login 状态码 302" "302" "$(status_of "$TMP/c3a.hdr")"
check_contains "3.2 跳转到 SSO /authorize" "/authorize?" "$AUTH_URL"
check_contains "3.3 PKCE S256" "code_challenge_method=S256" "$AUTH_URL"
check_contains "3.4 state 存在" "state=" "$AUTH_URL"

printf '$ curl -sS -o /dev/null -D - %s   # mocksso /authorize\n' "$AUTH_URL"
curl -sS -o /dev/null -D "$TMP/c3b.hdr" "$AUTH_URL"
cat "$TMP/c3b.hdr"
CB_URL="$(header_value "$TMP/c3b.hdr" Location)"
check_eq "3.5 authorize 状态码 302" "302" "$(status_of "$TMP/c3b.hdr")"
check_contains "3.6 回调 URL 指向 /_auth/callback" "/_auth/callback?" "$CB_URL"

printf '$ curl -sS --resolve %s -o /dev/null -D - %s\n' "a.example.com:18930:127.0.0.1" "$CB_URL"
curl -sS --resolve "a.example.com:18930:127.0.0.1" -o /dev/null -D "$TMP/c3c.hdr" "$CB_URL"
cat "$TMP/c3c.hdr"
C3COOKIE="$(cookie_header "$TMP/c3c.hdr")"
SID_A="$(printf '%s' "$C3COOKIE" | sed -n 's/.*__Host-appa_session=\([^;]*\).*/\1/p')"
check_eq "3.7 callback 状态码 302" "302" "$(status_of "$TMP/c3c.hdr")"
check_eq "3.8 跳回最初地址" "/deep/page?x=1" "$(header_value "$TMP/c3c.hdr" Location)"
check_contains "3.9 cookie 名 __Host-appa_session" "__Host-appa_session=" "$C3COOKIE"
check_contains "3.10 HttpOnly" "HttpOnly" "$C3COOKIE"
check_contains "3.11 Secure" "Secure" "$C3COOKIE"
check_contains "3.12 SameSite=Lax" "SameSite=Lax" "$C3COOKIE"
check_contains "3.13 Path=/" "Path=/" "$C3COOKIE"
check_not_contains "3.14 无 Domain 属性" "Domain=" "$C3COOKIE"
check_contains "3.15 Max-Age 7 天" "Max-Age=604800" "$C3COOKIE"

# ── 4. access with cookie ────────────────────────────────────────────────

title "4) 带 cookie 访问 → 200，上游收到 X-Auth-User"
printf '$ curl -sS -H %s -H %s http://%s/dash\n' "'Host: a.example.com:18930'" \
  "'Cookie: __Host-appa_session=<sid>'" "$GW_ADDR"
curl -sS -o "$TMP/c4.body" -w 'http_status=%{http_code}\n' -H "Host: $HOST_A" \
  -H "Cookie: __Host-appa_session=$SID_A" "http://$GW_ADDR/dash"
cat "$TMP/c4.body"; printf '\n'
check_eq "4.1 X-Auth-User 为登录用户" "mock-user-1" "$(json_str "$TMP/c4.body" x_auth_user)"
check_eq "4.2 X-Auth-App 正确" "appa" "$(json_str "$TMP/c4.body" x_auth_app)"
check_eq "4.3 X-Auth-Sid 正确" "$SID_A" "$(json_str "$TMP/c4.body" x_auth_sid)"

# ── 5. forged identity headers ───────────────────────────────────────────

title "5) 伪造 X-Auth-User: root → 被剥掉，上游只看到网关注入值"
printf '$ curl -sS -H %s -H %s -H %s -H %s http://%s/dash\n' \
  "'Host: a.example.com:18930'" "'Cookie: __Host-appa_session=<sid>'" \
  "'X-Auth-User: root'" "'Accept: application/json'" "$GW_ADDR"
curl -sS -o "$TMP/c5.body" -H "Host: $HOST_A" -H "Cookie: __Host-appa_session=$SID_A" \
  -H 'X-Auth-User: root' -H 'X-Auth-Email: root@example.com' -H 'X-Real-IP: 203.0.113.7' \
  -H 'Accept: application/json' "http://$GW_ADDR/dash"
cat "$TMP/c5.body"; printf '\n'
check_eq "5.1 X-Auth-User 仍是网关注入值" "mock-user-1" "$(json_str "$TMP/c5.body" x_auth_user)"
check_not_contains "5.2 伪造的 X-Auth-Email 未到达上游" "root@example.com" "$(cat "$TMP/c5.body")"
check_not_contains "5.3 伪造的 X-Real-IP 未到达上游" "203.0.113.7" "$(cat "$TMP/c5.body")"
check_not_contains "5.4 网关 cookie 未转发给上游" "__Host-appa_session" "$(cat "$TMP/c5.body")"

# ── 6. state replay / bogus ──────────────────────────────────────────────

title "6) state 重放 / 乱写 → 400"
printf '$ curl -sS -o /dev/null -w %%{http_code} -H %s "http://%s/_auth/callback?state=%s&code=x"\n' \
  "'Host: a.example.com:18930'" "$GW_ADDR" "$STATE_A"
REPLAY="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $HOST_A" "http://$GW_ADDR/_auth/callback?state=${STATE_A}&code=x")"
echo "replay(${STATE_A:0:8}...): $REPLAY"
printf '$ curl -sS -o /dev/null -w %%{http_code} -H %s "http://%s/_auth/callback?state=bogus&code=x"\n' \
  "'Host: a.example.com:18930'" "$GW_ADDR"
BOGUS="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $HOST_A" "http://$GW_ADDR/_auth/callback?state=bogus&code=x")"
echo "bogus: $BOGUS"
check_eq "6.1 已消费 state 重放 → 400" "400" "$REPLAY"
check_eq "6.2 乱写 state → 400" "400" "$BOGUS"

# ── 7. cross-app isolation ───────────────────────────────────────────────

title "7) 跨 app 隔离：A 的 cookie 访问 B → 不认"
printf '$ curl -sS -o body -w %%{http_code} -H %s -H %s -H %s http://%s/api/me\n' \
  "'Host: b.example.com:18930'" "'Cookie: __Host-appa_session=<A-sid>'" "'Accept: application/json'" "$GW_ADDR"
C7="$(curl -sS -o "$TMP/c7.body" -w '%{http_code}' -H "Host: $HOST_B" \
  -H "Cookie: __Host-appa_session=$SID_A" -H 'Accept: application/json' "http://$GW_ADDR/api/me")"
echo "status=$C7 body=$(cat "$TMP/c7.body")"
check_eq "7.1 跨 app 访问被拒 401" "401" "$C7"

# ── 8. WebSocket ─────────────────────────────────────────────────────────

title "8) WebSocket 握手 + 回显"
printf '$ wsprobe -addr %s -host %s -path /ws -cookie __Host-appa_session=<sid> -msg hello-ws\n' "$GW_ADDR" "$HOST_A"
WS_OUT="$("$TMP/bin/wsprobe" -addr "$GW_ADDR" -host "$HOST_A" -path /ws -cookie "__Host-appa_session=$SID_A" -msg hello-ws 2>&1)"
echo "$WS_OUT"
check_contains "8.1 握手 101" "HANDSHAKE 101" "$WS_OUT"
check_contains "8.2 回显成功" "ECHO hello-ws" "$WS_OUT"

# ── 9. large streaming body ──────────────────────────────────────────────

title "9) 大文件 50MB 流式转发（不 OOM）"
printf '$ curl -sS -o big.out -w %s -H %s -H %s "http://%s/big?mb=50"\n' \
  "'http=%{http_code} bytes=%{size_download}'" "'Host: a.example.com:18930'" \
  "'Cookie: __Host-appa_session=<sid>'" "$GW_ADDR"
BIG="$(curl -sS -o "$TMP/big.out" -w 'http=%{http_code} bytes=%{size_download} time=%{time_total}s' \
  -H "Host: $HOST_A" -H "Cookie: __Host-appa_session=$SID_A" "http://$GW_ADDR/big?mb=50")"
echo "$BIG"
check_contains "9.1 50MB 全部到达" "bytes=52428800" "$BIG"
check_contains "9.2 状态码 200" "http=200" "$BIG"
VMHWM_KB="$(awk '/VmHWM/{print $2}' "/proc/$GW_PID/status")"
note "gateway peak RSS (VmHWM) = ${VMHWM_KB} kB"
printf '$ grep VmHWM /proc/%s/status\n%s\n' "$GW_PID" "$(grep VmHWM "/proc/$GW_PID/status")"
if [ -n "$VMHWM_KB" ] && [ "$VMHWM_KB" -lt 102400 ]; then
  check_eq "9.3 内存峰值 < 100MB" "true" "true"
else
  check_eq "9.3 内存峰值 < 100MB" "true" "false ($VMHWM_KB kB)"
fi

# ── 10. logout + isolation ───────────────────────────────────────────────

title "10) 登出：A cookie 立即失效，B 不受影响"

# Log B in with the same stepwise flow.
curl -sS -o /dev/null -D "$TMP/b1.hdr" -H "Host: $HOST_B" "http://$GW_ADDR/_auth/login?next=%2Fb-home"
B_AUTH="$(header_value "$TMP/b1.hdr" Location)"
curl -sS -o /dev/null -D "$TMP/b2.hdr" "$B_AUTH"
B_CB="$(header_value "$TMP/b2.hdr" Location)"
curl -sS --resolve "b.example.com:18930:127.0.0.1" -o /dev/null -D "$TMP/b3.hdr" "$B_CB"
SID_B="$(cookie_header "$TMP/b3.hdr" | sed -n 's/.*__Host-appb_session=\([^;]*\).*/\1/p')"
echo "logged in B: sid=${SID_B:0:8}... status=$(status_of "$TMP/b3.hdr")"

printf '$ curl -sS -o /dev/null -D - -H %s -H %s http://%s/_auth/logout\n' \
  "'Host: a.example.com:18930'" "'Cookie: __Host-appa_session=<A-sid>'" "$GW_ADDR"
curl -sS -o /dev/null -D "$TMP/c10.hdr" -H "Host: $HOST_A" -H "Cookie: __Host-appa_session=$SID_A" "http://$GW_ADDR/_auth/logout"
cat "$TMP/c10.hdr"
LO_COOKIE="$(cookie_header "$TMP/c10.hdr")"
check_eq "10.1 logout 302" "302" "$(status_of "$TMP/c10.hdr")"
check_contains "10.2 清 A cookie" "__Host-appa_session=" "$LO_COOKIE"
check_contains "10.3 清 cookie Max-Age=0" "Max-Age=0" "$LO_COOKIE"
check_not_contains "10.4 未误清 B cookie" "__Host-appb_session" "$LO_COOKIE"

A_AFTER="$(curl -sS -o "$TMP/c10a.body" -w '%{http_code}' -H "Host: $HOST_A" \
  -H "Cookie: __Host-appa_session=$SID_A" -H 'Accept: application/json' "http://$GW_ADDR/api/me")"
echo "A after logout: status=$A_AFTER body=$(cat "$TMP/c10a.body")"
B_AFTER="$(curl -sS -o "$TMP/c10b.body" -w '%{http_code}' -H "Host: $HOST_B" \
  -H "Cookie: __Host-appb_session=$SID_B" -H 'Accept: application/json' "http://$GW_ADDR/api/me")"
echo "B after A logout: status=$B_AFTER body=$(cat "$TMP/c10b.body")"
check_eq "10.5 A 已失效 401" "401" "$A_AFTER"
check_eq "10.6 B 仍有效 200" "200" "$B_AFTER"

# ── 11. whitelist ────────────────────────────────────────────────────────

title "11) 白名单：配置外的 host → 404"
printf '$ curl -sS -o /dev/null -w %%{http_code} -H %s http://%s/\n' "'Host: evil.example.com'" "$GW_ADDR"
WL="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: evil.example.com' "http://$GW_ADDR/")"
echo "evil.example.com: $WL"
check_eq "11.1 未配置 host 返回 404" "404" "$WL"

# ── 12. reachability ─────────────────────────────────────────────────────

title "12) 可达性：只绑 127.0.0.1"
printf '$ ss -ltn | grep %s\n' "$GW_ADDR"
ss -ltn | grep "18930" || true
LISTEN="$(ss -ltn | awk '{print $4}' | grep '18930' || true)"
check_contains "12.1 监听在 127.0.0.1" "127.0.0.1:18930" "$LISTEN"
check_not_contains "12.2 未监听 0.0.0.0" "0.0.0.0:18930" "$LISTEN"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -n "$LAN_IP" ] && [ "${LAN_IP#127.}" = "$LAN_IP" ]; then
  printf '$ curl --connect-timeout 2 http://%s:18930/-/health\n' "$LAN_IP"
  if curl -sS --connect-timeout 2 "http://$LAN_IP:18930/-/health" >/dev/null 2>&1; then
    check_eq "12.3 非回环地址不可达" "unreachable" "reachable"
  else
    check_eq "12.3 非回环地址不可达" "unreachable" "unreachable"
  fi
else
  note "无额外非回环地址，跳过 12.3"
fi

# ── 13. proxy mode: bearer injection + encrypted token at rest (extra) ───

title "13) 追加：proxy 模式注入 Bearer + token 加密存放"
curl -sS -o /dev/null -D "$TMP/v1.hdr" -H "Host: $HOST_V2" "http://$GW_ADDR/_auth/login?next=%2Fv2-home"
V_AUTH="$(header_value "$TMP/v1.hdr" Location)"
curl -sS -o /dev/null -D "$TMP/v2.hdr" "$V_AUTH"
V_CB="$(header_value "$TMP/v2.hdr" Location)"
curl -sS --resolve "v2.example.com:18930:127.0.0.1" -o /dev/null -D "$TMP/v3.hdr" "$V_CB"
SID_V2="$(cookie_header "$TMP/v3.hdr" | sed -n 's/.*__Host-appv2_session=\([^;]*\).*/\1/p')"
echo "logged in v2: sid=${SID_V2:0:8}... status=$(status_of "$TMP/v3.hdr")"

printf '$ curl -sS -H %s -H %s -H %s http://%s/api/data\n' \
  "'Host: v2.example.com:18930'" "'Cookie: __Host-appv2_session=<sid>'" \
  "'Accept: application/json'" "$GW_ADDR"
curl -sS -o "$TMP/c13.body" -H "Host: $HOST_V2" -H "Cookie: __Host-appv2_session=$SID_V2" \
  -H 'Accept: application/json' "http://$GW_ADDR/api/data"
cat "$TMP/c13.body"; printf '\n'
check_contains "13.1 上游收到 Bearer access_token" '"authorization":"Bearer at-' "$(cat "$TMP/c13.body")"

RAW_SESS="$(redis-cli -n 2 GET "${PREFIX}sess:${SID_V2}")"
printf '$ redis-cli -n 2 GET %ssess:<sid>\n%s\n' "$PREFIX" "$RAW_SESS"
check_not_contains "13.2 Redis 中无明文 access_token" "at-" "$RAW_SESS"
check_contains "13.3 Redis 中为密文 access_token 字段" '"access_token":"' "$RAW_SESS"

# ── 14. missing token key aborts startup (extra) ─────────────────────────

title "14) 追加：token 密钥文件缺失 → 启动报错（不退化为明文）"
sed "s#${TMP}/token.key#${TMP}/does-not-exist.key#" "$TMP/config.yaml" > "$TMP/bad.yaml"
printf '$ %s/auth-gateway -config %s/bad.yaml\n' "$TMP" "$TMP"
BAD_OUT="$("$TMP/bin/auth-gateway" -config "$TMP/bad.yaml" 2>&1)"
BAD_RC=$?
printf '%s\n' "$BAD_OUT"
printf 'exit=%d\n' "$BAD_RC"
if [ "$BAD_RC" -ne 0 ]; then
  check_eq "14.1 缺密钥时非零退出" "true" "true"
else
  check_eq "14.1 缺密钥时非零退出" "true" "false"
fi
check_contains "14.2 报错指向 token 密钥" "token encryption key" "$BAD_OUT"

# ── 15. path-routed auth (routes) ───────────────────────────────────────

title "15) 按路径分流：最长前缀、required/none 差异、伪造头剥离、WS、先登录后可用"

printf '$ curl -sS -o /dev/null -D - -H %s http://%s/api/xyz\n' "'Host: r.example.com:18930'" "$GW_ADDR"
curl -sS -o /dev/null -D "$TMP/r1.hdr" -H "Host: $HOST_R" "http://$GW_ADDR/api/xyz"
cat "$TMP/r1.hdr"
check_eq "15.1 最长前缀命中 required：未登录导航 302" "302" "$(status_of "$TMP/r1.hdr")"
check_eq "15.2 302 指向登录并带 next" "/_auth/login?next=%2Fapi%2Fxyz" "$(header_value "$TMP/r1.hdr" Location)"

R_API="$(curl -sS -o "$TMP/r2.body" -w '%{http_code}' -H "Host: $HOST_R" -H 'Accept: application/json' "http://$GW_ADDR/api/xyz")"
echo "required API: status=$R_API body=$(cat "$TMP/r2.body")"
check_eq "15.3 required 路径 API 语义 401" "401" "$R_API"
check_contains "15.4 401 JSON body" '"error":"unauthenticated"' "$(cat "$TMP/r2.body")"

R_PUB="$(curl -sS -o "$TMP/r3.body" -D "$TMP/r3.hdr" -w '%{http_code}' -H "Host: $HOST_R" "http://$GW_ADDR/")"
cat "$TMP/r3.body"; printf '\n'
check_eq "15.5 none 路径未登录正常 200 反代" "200" "$R_PUB"
check_eq "15.6 none 路径不注入 X-Auth-User" "" "$(json_str "$TMP/r3.body" x_auth_user)"
check_not_contains "15.7 none 路径不下发网关 cookie" "__Host-appr_session" "$(cat "$TMP/r3.hdr")"

curl -sS -o "$TMP/r4.body" -H "Host: $HOST_R" -H 'X-Auth-User: root' -H 'X-Auth-Email: root@example.com' "http://$GW_ADDR/"
cat "$TMP/r4.body"; printf '\n'
check_eq "15.8 none 路径伪造 X-Auth-User 被剥掉" "" "$(json_str "$TMP/r4.body" x_auth_user)"
check_not_contains "15.9 伪造 X-Auth-Email 未到达上游" "root@example.com" "$(cat "$TMP/r4.body")"

R_ME="$(curl -sS -o "$TMP/r5.body" -w '%{http_code}' -H "Host: $HOST_R" -H 'Accept: application/json' "http://$GW_ADDR/_auth/me")"
check_eq "15.10 /_auth/me 在 routes app 上仍由网关处理（未登录 401）" "401" "$R_ME"
check_contains "15.11 /_auth/me 返回网关 JSON" '"error":"unauthenticated"' "$(cat "$TMP/r5.body")"

# none 页面主动登录 → 同站 required 路由立即可用
curl -sS -o /dev/null -D "$TMP/r6.hdr" -H "Host: $HOST_R" "http://$GW_ADDR/_auth/login?next=%2Fapi%2Fdata"
R_AUTH="$(header_value "$TMP/r6.hdr" Location)"
check_eq "15.12 none 页面可主动登录：302" "302" "$(status_of "$TMP/r6.hdr")"
check_contains "15.13 登录跳 SSO authorize" "/authorize?" "$R_AUTH"
curl -sS -o /dev/null -D "$TMP/r7.hdr" "$R_AUTH"
R_CB="$(header_value "$TMP/r7.hdr" Location)"
curl -sS --resolve "r.example.com:18930:127.0.0.1" -o /dev/null -D "$TMP/r8.hdr" "$R_CB"
SID_R="$(cookie_header "$TMP/r8.hdr" | sed -n 's/.*__Host-appr_session=\([^;]*\).*/\1/p')"
echo "logged in appr: sid=${SID_R:0:8}... status=$(status_of "$TMP/r8.hdr")"
check_contains "15.14 登录成功下发网关 cookie" "__Host-appr_session=" "$(cookie_header "$TMP/r8.hdr")"
R_AFTER="$(curl -sS -o "$TMP/r9.body" -w '%{http_code}' -H "Host: $HOST_R" -H "Cookie: __Host-appr_session=$SID_R" -H 'Accept: application/json' "http://$GW_ADDR/api/data")"
cat "$TMP/r9.body"; printf '\n'
check_eq "15.15 登录后 required 路由 200" "200" "$R_AFTER"
check_eq "15.16 required 路由注入登录身份" "mock-user-1" "$(json_str "$TMP/r9.body" x_auth_user)"

printf '$ wsprobe -addr %s -host %s -path /v2ws -msg pub-ws\n' "$GW_ADDR" "$HOST_R"
WS_PUB="$("$TMP/bin/wsprobe" -addr "$GW_ADDR" -host "$HOST_R" -path /v2ws -msg pub-ws 2>&1)"
echo "$WS_PUB"
check_contains "15.17 none 路由 WS 握手 101" "HANDSHAKE 101" "$WS_PUB"
check_contains "15.18 none 路由 WS 回显" "ECHO pub-ws" "$WS_PUB"

R_NR="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $HOST_NR" "http://$GW_ADDR/other")"
echo "unmatched path on appnr: $R_NR"
check_eq "15.19 未命中任何 prefix → 404（不降级为公开反代）" "404" "$R_NR"

AUDIT_BEFORE="$(wc -l < "$TMP/audit.log" | tr -d ' ')"
curl -sS -o /dev/null -H "Host: $HOST_R" "http://$GW_ADDR/"
AUDIT_AFTER="$(wc -l < "$TMP/audit.log" | tr -d ' ')"
echo "audit lines before=$AUDIT_BEFORE after=$AUDIT_AFTER"
check_eq "15.20 none 路由默认不写审计" "$AUDIT_BEFORE" "$AUDIT_AFTER"

# ── 16. routes config validation aborts startup ──────────────────────────

title "16) 启动校验：routes 配置不合法必须报错退出（不静默降级）"

mk_bad_config() { # file, routes-body
  cat > "$1" <<EOF
listen: 127.0.0.1:18940
issuer: http://${SSO_ADDR}
redis:
  addr: 127.0.0.1:6379
  db: 2
  prefix: "${PREFIX}bad:"
audit:
  file: ${TMP}/audit-bad.log
apps:
  - id: br
    hosts: [br.example.com]
    secret_file: ${TMP}/appa.secret
    routes:
$2
EOF
}

mk_bad_config "$TMP/badprefix.yaml" "      - prefix: bad
        upstream: http://${UP_ADDR}
        auth: required"
BADP_OUT="$("$TMP/bin/auth-gateway" -config "$TMP/badprefix.yaml" 2>&1)"; BADP_RC=$?
printf '%s\nexit=%d\n' "$BADP_OUT" "$BADP_RC"
check_eq "16.1 prefix 不以 / 开头 → 非零退出" "true" "$([ "$BADP_RC" -ne 0 ] && echo true || echo false)"
check_contains "16.2 报错指出 prefix" "prefix" "$BADP_OUT"

mk_bad_config "$TMP/badup.yaml" "      - prefix: /api/
        auth: required"
BADU_OUT="$("$TMP/bin/auth-gateway" -config "$TMP/badup.yaml" 2>&1)"; BADU_RC=$?
printf '%s\nexit=%d\n' "$BADU_OUT" "$BADU_RC"
check_eq "16.3 routes upstream 缺失 → 非零退出" "true" "$([ "$BADU_RC" -ne 0 ] && echo true || echo false)"
check_contains "16.4 报错指出 routes upstream" "routes[0].upstream" "$BADU_OUT"

mk_bad_config "$TMP/badauth.yaml" "      - prefix: /api/
        upstream: http://${UP_ADDR}
        auth: bogus"
BADA_OUT="$("$TMP/bin/auth-gateway" -config "$TMP/badauth.yaml" 2>&1)"; BADA_RC=$?
printf '%s\nexit=%d\n' "$BADA_OUT" "$BADA_RC"
check_eq "16.5 auth 非法 → 非零退出" "true" "$([ "$BADA_RC" -ne 0 ] && echo true || echo false)"
check_contains "16.6 报错指出 auth" "auth" "$BADA_OUT"

# ── 17. client bearer (accept_bearer) ────────────────────────────────────

title "17) 客户端 Bearer：默认关、合法放行、失败 401 不碰 cookie、cookie 优先"

mint_token() { # query-string
  curl -sS "http://$SSO_ADDR/test/mint?$1" | grep -o '"token":"[^"]*"' | head -1 | sed 's/.*:"//; s/"$//'
}

# 17.1 安全默认：未写 accept_bearer 的 app（appa）带合法 Bearer 仍然 401。
TOK_APPA="$(mint_token 'sub=mock-user-1&aud=appa&exp_in=3600')"
SD="$(curl -sS -o "$TMP/b_sd.body" -D "$TMP/b_sd.hdr" -w '%{http_code}' -H "Host: $HOST_A" \
  -H "Authorization: Bearer $TOK_APPA" -H 'Accept: application/json' "http://$GW_ADDR/api/data")"
printf '$ curl -sS -H %s -H %s http://%s/api/data\n' "'Host: a.example.com:18930'" \
  "'Authorization: Bearer <valid, aud=appa>'" "$GW_ADDR"
echo "safe-default appa: status=$SD body=$(cat "$TMP/b_sd.body")"
check_eq "17.1 accept_bearer 默认关：合法 Bearer 仍 401" "401" "$SD"
check_contains "17.2 401 body 为 unauthenticated" '"error":"unauthenticated"' "$(cat "$TMP/b_sd.body")"

# 17.3 accept_bearer: true + 合法 Bearer（aud=admin）→ 200，上游收到 X-Auth-User=sub。
SUBB="app-user-9"
TOK_OK="$(mint_token "sub=$SUBB&aud=admin&exp_in=3600")"
OK="$(curl -sS -o "$TMP/b_ok.body" -D "$TMP/b_ok.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_OK" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
cat "$TMP/b_ok.body"; printf '\n'
check_eq "17.3 合法 Bearer → 200" "200" "$OK"
check_eq "17.4 上游收到 X-Auth-User=sub" "$SUBB" "$(json_str "$TMP/b_ok.body" x_auth_user)"
check_eq "17.5 上游收到 X-Auth-App=appbear" "appbear" "$(json_str "$TMP/b_ok.body" x_auth_app)"
check_eq "17.6 成功响应不含任何 Set-Cookie" "" "$(cookie_header "$TMP/b_ok.hdr")"

# 17.7 过期 → 401，且不设/不清 cookie。
TOK_EXP="$(mint_token 'sub=u&aud=admin&exp_in=-3600')"
EXP="$(curl -sS -o "$TMP/b_exp.body" -D "$TMP/b_exp.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_EXP" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
echo "expired: status=$EXP body=$(cat "$TMP/b_exp.body")"
check_eq "17.7 过期 Bearer → 401" "401" "$EXP"
check_eq "17.8 过期失败不碰 cookie" "" "$(cookie_header "$TMP/b_exp.hdr")"

# 17.9 aud 不在白名单 → 401。
TOK_AUD="$(mint_token 'sub=u&aud=other&exp_in=3600')"
AUD="$(curl -sS -o /dev/null -D "$TMP/b_aud.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_AUD" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
echo "bad aud: status=$AUD"
check_eq "17.9 aud 不在白名单 → 401" "401" "$AUD"
check_eq "17.10 aud 失败不碰 cookie" "" "$(cookie_header "$TMP/b_aud.hdr")"

# 17.11 alg:none → 401（算法混淆防护）。
TOK_NONE="$(mint_token 'sub=u&aud=admin&alg=none&exp_in=3600')"
NONE="$(curl -sS -o /dev/null -D "$TMP/b_none.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_NONE" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
echo "alg none: status=$NONE"
check_eq "17.11 alg:none → 401" "401" "$NONE"
check_eq "17.12 alg:none 失败不碰 cookie" "" "$(cookie_header "$TMP/b_none.hdr")"

# 17.13 篡改签名 → 401。
IFS='.' read -r TOK_H TOK_P TOK_S <<< "$TOK_OK"
TOK_TAMPERED="$TOK_H.$TOK_P.$(printf '%s' "$TOK_S" | sed 's/^\(.\)\(.\)/\2\1/')"
TAM="$(curl -sS -o /dev/null -D "$TMP/b_tam.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_TAMPERED" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
echo "tampered: status=$TAM"
check_eq "17.13 篡改签名 → 401" "401" "$TAM"
check_eq "17.14 篡改失败不碰 cookie" "" "$(cookie_header "$TMP/b_tam.hdr")"

# 17.15 jti 在撤销黑名单 → 401（复用 gw:revoked:<jti>）。
TOK_REV="$(mint_token 'sub=u&aud=admin&jti=jti-revoke-1&exp_in=3600')"
redis-cli -n 2 SET "${PREFIX}revoked:jti-revoke-1" 1 >/dev/null
REV="$(curl -sS -o /dev/null -D "$TMP/b_rev.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_REV" -H 'Accept: application/json' "http://$GW_ADDR/dash")"
redis-cli -n 2 DEL "${PREFIX}revoked:jti-revoke-1" >/dev/null
echo "revoked jti: status=$REV"
check_eq "17.15 已撤销 jti → 401" "401" "$REV"
check_eq "17.16 撤销失败不碰 cookie" "" "$(cookie_header "$TMP/b_rev.hdr")"

# 17.17 cookie 有效且同时带 Bearer → 走 cookie（浏览器行为不变）。
curl -sS -o /dev/null -D "$TMP/b1.hdr" -H "Host: $HOST_BEAR" "http://$GW_ADDR/_auth/login?next=%2Fdash"
BB_AUTH="$(header_value "$TMP/b1.hdr" Location)"
curl -sS -o /dev/null -D "$TMP/b2.hdr" "$BB_AUTH"
BB_CB="$(header_value "$TMP/b2.hdr" Location)"
curl -sS --resolve "bear.example.com:18930:127.0.0.1" -o /dev/null -D "$TMP/b3.hdr" "$BB_CB"
SID_BEAR="$(cookie_header "$TMP/b3.hdr" | sed -n 's/.*__Host-appbear_session=\([^;]*\).*/\1/p')"
echo "logged in appbear: sid=${SID_BEAR:0:8}..."
TOK_OTHER="$(mint_token 'sub=app-bearer-user&aud=admin&exp_in=3600')"
BOTH="$(curl -sS -o "$TMP/b_both.body" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Cookie: __Host-appbear_session=$SID_BEAR" -H "Authorization: Bearer $TOK_OTHER" \
  -H 'Accept: application/json' "http://$GW_ADDR/dash")"
cat "$TMP/b_both.body"; printf '\n'
check_eq "17.17 cookie+Bearer → 200" "200" "$BOTH"
check_eq "17.18 cookie 优先（上游看到 cookie 的 sub）" "mock-user-1" "$(json_str "$TMP/b_both.body" x_auth_user)"

# 17.19 auth:none 路由即使带合法 Bearer 也不注入身份头（公开路径依旧公开）。
TOK_R="$(mint_token 'sub=app-bearer-user&aud=appr&exp_in=3600')"
NONE_RT="$(curl -sS -o "$TMP/b_none_rt.body" -w '%{http_code}' -H "Host: $HOST_R" \
  -H "Authorization: Bearer $TOK_R" -H 'Accept: application/json' "http://$GW_ADDR/")"
cat "$TMP/b_none_rt.body"; printf '\n'
check_eq "17.19 none 路由带 Bearer 仍 200" "200" "$NONE_RT"
check_eq "17.20 none 路由不注入 X-Auth-User" "" "$(json_str "$TMP/b_none_rt.body" x_auth_user)"

# 17.21 /_auth/* 行为完全不变：带合法 Bearer 的 /_auth/me 仍 401。
ME_B="$(curl -sS -o "$TMP/b_me.body" -D "$TMP/b_me.hdr" -w '%{http_code}' -H "Host: $HOST_BEAR" \
  -H "Authorization: Bearer $TOK_OK" -H 'Accept: application/json' "http://$GW_ADDR/_auth/me")"
echo "/_auth/me with bearer: status=$ME_B body=$(cat "$TMP/b_me.body")"
check_eq "17.21 /_auth/me 不认 Bearer（行为不变）" "401" "$ME_B"

# 17.22 proxy 模式 app（appv2，无 accept_bearer）带合法 Bearer → 401，两个开关互不相干。
TOK_V2="$(mint_token 'sub=u&aud=appv2&exp_in=3600')"
V2B="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $HOST_V2" \
  -H "Authorization: Bearer $TOK_V2" -H 'Accept: application/json' "http://$GW_ADDR/api/data")"
echo "proxy-mode app with bearer: status=$V2B"
check_eq "17.22 mode:proxy 未开 accept_bearer：Bearer 仍 401" "401" "$V2B"

# ── summary ──────────────────────────────────────────────────────────────

title "汇总"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf 'failed cases:\n'
  for c in "${FAILED_CASES[@]}"; do printf '  - %s\n' "$c"; done
  exit 1
fi
printf 'ALL CASES PASSED\n'
