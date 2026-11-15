#!/usr/bin/env bash
#
# bootstrap.sh (wrapper) — the only client script built into the server image.
# Small and stable on purpose: it does the one thing that must not change
# casually, which is deciding whether to trust the server. Then it downloads
# the real installer (client/bootstrap.sh, a plain file the server reads live
# from its client/ folder) over the pinned connection and runs it.
#
#   curl -kfsSL https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]
#   wget -qO- --no-check-certificate https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]
#
# Trust: pass PB_PIN=sha256//... (shown on the server's admin page) to verify
# the server's TLS key strictly. Without it, the pin is shown and you are asked
# to confirm it (trust on first use); --yes / -y skips the question.
#
# Every option is passed on to the installer; see client/bootstrap.sh.
#
set -Eeuo pipefail
# Same patterns and tool output on every machine, whatever its locale.
export LC_ALL=C

# Everything is inside { ... } so bash reads the whole script before running
# any of it — required when the script arrives on stdin through a pipe.
{
BASE_URL="__BASE_URL__"            # filled in by the server for each request
SYNC_MINUTES="__SYNC_MINUTES__"
DEFAULT_USER="__DEFAULT_USER__"
HAS_PAYLOAD="__HAS_PAYLOAD__"
PAYLOAD_ENTRY="__PAYLOAD_ENTRY__"

have_tty() { { : < /dev/tty; } 2>/dev/null; }
say()  { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "Run as root: ... | sudo bash -s -- [options]"
[[ "$BASE_URL" == https://* ]] || die "The server address was not filled in ('$BASE_URL'). Download this script from the server itself."

# The only option the wrapper itself cares about (options after -- belong to
# the payload's entry script).
AUTO_YES=false
for arg in "$@"; do
  case "$arg" in
    --) break ;;
    --yes|-y) AUTO_YES=true ;;
  esac
done

hostport="${BASE_URL#https://}"; hostport="${hostport%%/*}"
if [[ "$hostport" == \[* ]]; then
  host="${hostport%%]*}"; host="${host#[}"; port="${hostport##*]}"; port="${port#:}"
else
  host="${hostport%:*}"; port="${hostport##*:}"; [[ "$host" == "$port" ]] && port=""
fi
port="${port:-443}"

# --- prerequisites ------------------------------------------------------------
need=()
command -v curl &>/dev/null || need+=(curl)
command -v openssl &>/dev/null || need+=(openssl)
if [[ ${#need[@]} -gt 0 ]]; then
  say "Installing ${need[*]}"
  if   command -v apt-get &>/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates "${need[@]}" >/dev/null
  elif command -v dnf     &>/dev/null; then dnf install -y -q "${need[@]}" >/dev/null
  elif command -v yum     &>/dev/null; then yum install -y -q "${need[@]}" >/dev/null
  elif command -v apk     &>/dev/null; then apk add --no-cache "${need[@]}" >/dev/null
  elif command -v zypper  &>/dev/null; then zypper -q install -y "${need[@]}" >/dev/null
  elif command -v pacman  &>/dev/null; then pacman -Sy --noconfirm "${need[@]}" >/dev/null
  else die "Please install ${need[*]} and run this again."
  fi
fi

# --- pin the server's TLS key -----------------------------------------------
seen_pin="$(openssl s_client -connect "${host}:${port}" -servername "$host" </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary | openssl base64 -A)"
# (the second value is the hash of empty input: nothing was read)
[[ -n "$seen_pin" && "$seen_pin" != "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" ]] \
  || die "Could not read a TLS key from ${host}:${port}."
PIN="sha256//${seen_pin}"

if [[ -n "${PB_PIN:-}" ]]; then
  [[ "$PB_PIN" == "$PIN" ]] || die "TLS pin mismatch! Expected $PB_PIN, the server presented $PIN. Not continuing."
  say "TLS pin verified: $PIN"
else
  say "The server presented TLS pin:  $PIN"
  say "It must match the pin on the server's admin page (or in its log)."
  if ! $AUTO_YES; then
    have_tty || die "No terminal to confirm the pin. Run again with PB_PIN=$PIN"
    read -r -p "Does it match? [y/N] " ans < /dev/tty
    [[ "$ans" =~ ^[Yy]$ ]] || die "Pin not confirmed."
  fi
fi

# --- hand over to the installer ---------------------------------------------------
MAIN="$(mktemp)"
trap 'rm -f "$MAIN"' EXIT
curl -fsS --proto '=https' --retry 3 --retry-delay 2 --max-time 60 -k --pinnedpubkey "$PIN" \
     -o "$MAIN" "${BASE_URL}/client/bootstrap.sh" \
  || die "Could not download the installer (client/bootstrap.sh) from the server. Is its client/ folder in place?"
head -n1 "$MAIN" | grep -q '^#!' || die "The server did not return a script for client/bootstrap.sh."

rc=0
PB_BASE_URL="$BASE_URL" PB_SERVER_PIN="$PIN" PB_SYNC_MINUTES="$SYNC_MINUTES" PB_DEFAULT_USER="$DEFAULT_USER" \
PB_HAS_PAYLOAD="$HAS_PAYLOAD" PB_PAYLOAD_ENTRY="$PAYLOAD_ENTRY" \
  bash "$MAIN" "$@" < /dev/null || rc=$?
exit "$rc"
}
