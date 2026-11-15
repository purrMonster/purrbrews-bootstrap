#!/usr/bin/env bash
#
# purrbrews-bootstrap-sync — keep one user's authorized_keys in step with the
# bootstrap server's list of public keys.
#
# Behaviour:
#   - Keys live in a managed block inside ~USER/.ssh/authorized_keys. Lines
#     outside the block (added by hand) are never touched.
#   - Removing a key on the server removes it here on the next sync.
#   - Fail-safe: if the server cannot be reached, or the result would be zero
#     keys, nothing is changed. An outage must never look like "revoke all".
#   - The server is trusted by its pinned TLS key, not by a certificate authority.
#   - Exit codes: 0 ok, 75 the server was unreachable (temporary, nothing
#     changed), 1 anything else (including a TLS pin mismatch).
#
# Usage:  purrbrews-bootstrap-sync [--config FILE] [--dry-run]
#   Config defaults to /etc/purrbrews-bootstrap/client.conf (KEY=value lines).
#
set -Eeuo pipefail

CONFIG="/etc/purrbrews-bootstrap/client.conf"
DRY_RUN=false
BEGIN_MARK="# >>> purrbrews-bootstrap managed keys — edits inside this block are overwritten >>>"
END_MARK="# <<< purrbrews-bootstrap managed keys <<<"

log()  { printf '[key-sync] %s\n' "$*"; }
die()  { printf '[key-sync] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)  CONFIG="${2:?--config needs a path}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# Minimal KEY=value reader: nothing in the file is ever executed.
SERVER_URL=""; SERVER_PIN=""; KEY_USER=""; CLIENT_NAME=""; CLIENT_ID=""; AUTHORIZED_KEYS_FILE=""
[[ -f "$CONFIG" ]] || die "No config at $CONFIG. Run the server's bootstrap.sh first."
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  key="${line%%=*}"; val="${line#*=}"
  case "$key" in
    SERVER_URL|SERVER_PIN|KEY_USER|CLIENT_NAME|CLIENT_ID|AUTHORIZED_KEYS_FILE) printf -v "$key" '%s' "$val" ;;
  esac
done < "$CONFIG"

[[ "$SERVER_URL" == https://* ]]              || die "SERVER_URL in $CONFIG must start with https://"
[[ "$SERVER_PIN" == sha256//* ]]              || die "SERVER_PIN in $CONFIG must look like sha256//..."
[[ "$KEY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "KEY_USER in $CONFIG is not a valid user name."
id "$KEY_USER" &>/dev/null                    || die "User '$KEY_USER' does not exist."

if [[ -n "$AUTHORIZED_KEYS_FILE" ]]; then
  AK_FILE="$AUTHORIZED_KEYS_FILE"
else
  home_dir="$(getent passwd "$KEY_USER" 2>/dev/null | cut -d: -f6 || true)"
  [[ -n "$home_dir" ]] || home_dir="$(eval "printf '%s' ~${KEY_USER}")"   # name validated above
  [[ -d "$home_dir" ]] || die "Home directory of '$KEY_USER' not found."
  AK_FILE="${home_dir}/.ssh/authorized_keys"
fi
key_group="$(id -gn "$KEY_USER")"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- fetch ------------------------------------------------------------------------
rc=0
curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 20 --retry 2 --retry-delay 2 \
     -k --pinnedpubkey "$SERVER_PIN" \
     -H "X-Bootstrap-Client: ${CLIENT_NAME}" -H "X-Bootstrap-Id: ${CLIENT_ID}" -H "X-Bootstrap-User: ${KEY_USER}" \
     -o "$TMP/src" "${SERVER_URL}/keys/authorized_keys" || rc=$?
case "$rc" in
  0) ;;
  90|60|35|51|58) die "TLS check failed for ${SERVER_URL} (curl exit $rc): a different key answered than the pinned one. Leaving authorized_keys unchanged." ;;
  22) die "The server refused the request (curl exit 22). Leaving authorized_keys unchanged." ;;
  *) printf '[key-sync] UNREACHABLE: %s (curl exit %s) — leaving authorized_keys unchanged.\n' "$SERVER_URL" "$rc" >&2; exit 75 ;;
esac

# --- validate -----------------------------------------------------------------------
# Only plain public keys: no authorized_keys options (command=, from=, ...).
grep -q 'PRIVATE KEY' "$TMP/src" && die "The server sent something that looks like a private key. Leaving authorized_keys unchanged."
key_re='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*( [ -~]*)?$'
: > "$TMP/keys"
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  if [[ "$line" =~ $key_re ]]; then printf '%s\n' "$line" >> "$TMP/keys"
  else printf '[key-sync] WARNING: ignoring a line that is not a plain public key.\n' >&2; fi
done < "$TMP/src"
sort -u "$TMP/keys" -o "$TMP/keys"
count="$(wc -l < "$TMP/keys" | tr -d ' ')"
[[ "$count" -gt 0 ]] || die "The server returned zero valid keys — refusing to empty authorized_keys."

# --- build the new file ----------------------------------------------------------------
: > "$TMP/outside"
if [[ -f "$AK_FILE" ]]; then
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    !skip {print}' "$AK_FILE" > "$TMP/outside"
fi
{
  # Hand-added lines first, without trailing blank lines.
  awk '{ lines[NR]=$0 } END { n=NR; while (n>0 && lines[n]=="") n--; for (i=1;i<=n;i++) print lines[i] }' "$TMP/outside"
  printf '%s\n' "$BEGIN_MARK"
  cat "$TMP/keys"
  printf '%s\n' "$END_MARK"
} > "$TMP/new_ak"

if [[ -f "$AK_FILE" ]] && cmp -s "$TMP/new_ak" "$AK_FILE"; then
  log "authorized_keys already up to date for $KEY_USER ($count key(s))."
  exit 0
fi
if $DRY_RUN; then
  log "dry run: would write $count key(s) to $AK_FILE"
  exit 0
fi

# --- install (atomic) ------------------------------------------------------------------
ak_dir="$(dirname "$AK_FILE")"
if [[ ! -d "$ak_dir" ]]; then
  mkdir -p "$ak_dir"; chmod 700 "$ak_dir"
  [[ "$(id -u)" -eq 0 ]] && chown "$KEY_USER:$key_group" "$ak_dir"
fi
cp "$TMP/new_ak" "${AK_FILE}.bootstrap-tmp"
chmod 600 "${AK_FILE}.bootstrap-tmp"
[[ "$(id -u)" -eq 0 ]] && chown "$KEY_USER:$key_group" "${AK_FILE}.bootstrap-tmp"
mv -f "${AK_FILE}.bootstrap-tmp" "$AK_FILE"
log "authorized_keys updated for $KEY_USER: $count key(s) from ${SERVER_URL}."
