#!/usr/bin/env bash
# Repository hygiene scan for BRIEF section 0: no real domains, private IPs,
# private host paths or secret material may be committed.
#
# Patterns are assembled from placeholders so this script itself contains no
# real secret values. Documentation IP ranges (RFC 5737) and the loopback
# address are explicitly allowed; everything else fails the scan.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

HITS=0
hit() { printf 'HIT  %s\n' "$1"; HITS=$((HITS + 1)); }

# Files tracked by git only: untracked runtime artifacts are irrelevant.
mapfile -t FILES < <(git ls-files)
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "no tracked files"
  exit 0
fi

# 1) PEM / private-key material. The marker is split so the literal never
#    appears here in one piece.
MARKER="PRIVATE"" KEY"
PEM_RE="BEGIN [A-Z0-9 ]*${MARKER}"
while IFS= read -r line; do
  [ -n "$line" ] && hit "PEM key material: $line"
done < <(grep -nE "$PEM_RE" "${FILES[@]}" 2>/dev/null || true)

# 2) IPv4 addresses outside the allowlist (loopback + RFC 5737 doc ranges).
IP_RE='([0-9]{1,3}\.){3}[0-9]{1,3}'
while IFS= read -r line; do
  [ -z "$line" ] && continue
  ip="${line##*:}"
  case "$ip" in
    127.0.0.1|0.0.0.0) continue ;;
  esac
  # RFC 5737 documentation ranges only.
  case "$ip" in
    192.0.2.*|198.51.100.*|203.0.113.*) continue ;;
  esac
  hit "non-allowlisted IPv4: $line"
done < <(grep -nEo "$IP_RE" "${FILES[@]}" 2>/dev/null || true)

# 3) Domains outside the example.com / example.org / localhost allowlist.
URL_RE='[A-Za-z0-9][A-Za-z0-9._-]*\.(com|net|org|cn|io)'
while IFS= read -r line; do
  [ -z "$line" ] && continue
  host="${line##*:}"
  host="${host#https://}"; host="${host#http://}"
  case "$host" in
    example.com|*.example.com|example.org|*.example.org|localhost|*.localhost) continue ;;
  esac
  hit "non-example domain: $line"
done < <(grep -nEo "$URL_RE" "${FILES[@]}" 2>/dev/null || true)

# 4) Private host paths. The markers are split so this script does not match
#    itself when scanned.
ROOT_DIR_PAT="/ro""ot/"
HOME_PROJ_PAT="/ho""me/[a-z]+/proj"
while IFS= read -r line; do
  [ -n "$line" ] && hit "private host path: $line"
done < <(grep -nE "${ROOT_DIR_PAT}|${HOME_PROJ_PAT}" "${FILES[@]}" 2>/dev/null || true)

# 5) Long high-entropy assignments to secret-ish names.
SECRET_RE='(secret|password|passwd|token|api[_-]?key|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/=_-]{24,}'
while IFS= read -r line; do
  [ -n "$line" ] && hit "possible inline secret: $line"
done < <(grep -nEi "$SECRET_RE" "${FILES[@]}" 2>/dev/null || true)

echo "----"
if [ "$HITS" -eq 0 ]; then
  echo "private-info scan: 0 hits across ${#FILES[@]} tracked files"
  exit 0
fi
echo "private-info scan: ${HITS} hit(s) — fix before committing"
exit 1
