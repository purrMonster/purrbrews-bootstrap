#!/usr/bin/env bash
#
# bootstrap.sh — served by a purrbrews-bootstrap server. On a new machine:
#
#   curl -kfsSL https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]
#   wget -qO- --no-check-certificate https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]
#
# What it does:
#   1. Pins the server's TLS key. Pass PB_PIN=sha256//... (shown on the server's
#      admin page) to verify it strictly; otherwise it shows the pin and asks
#      you to confirm it (trust on first use). Everything after uses the pin.
#   2. Installs the key-sync script and its settings, and syncs the SSH public
#      keys into the chosen user's authorized_keys (a managed block; lines you
#      added by hand are left alone).
#   3. Schedules the sync (systemd timer, or cron where there is no systemd).
#   4. If the server carries a payload, downloads it, checks it against
#      SHA256SUMS, and runs its entry script when one is configured.
#
# Options:
#   --user NAME     whose authorized_keys to manage (default: the server's
#                   default user, else the user who ran sudo, else root)
#   --name NAME     how this machine appears in the server's client list
#                   (default: its hostname)
#   --skip-keys     do not set up key sync (payload only)
#   --yes, -y       do not ask to confirm the pin (trust on first use)
#   --              everything after this goes to the payload's entry script
#
# Environment:
#   PB_PIN=sha256//...   expected TLS public-key pin
#
set -Eeuo pipefail

# Everything is inside { ... } so bash reads the whole script before running
# any of it — required when the script arrives on stdin through a pipe.
{
BASE_URL="__BASE_URL__"            # filled in by the server for each request
SYNC_MINUTES="__SYNC_MINUTES__"
DEFAULT_USER="__DEFAULT_USER__"
HAS_PAYLOAD="__HAS_PAYLOAD__"
PAYLOAD_ENTRY="__PAYLOAD_ENTRY__"

ETC_DIR="/etc/purrbrews-bootstrap"
VAR_DIR="/var/lib/purrbrews-bootstrap"
SYNC_BIN="/usr/local/sbin/purrbrews-bootstrap-sync"
UNIT="purrbrews-bootstrap-sync"

have_tty() { { : < /dev/tty; } 2>/dev/null; }
say()  { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "Run as root: ... | sudo bash -s -- [options]"
[[ "$BASE_URL" == https://* ]] || die "The server address was not filled in ('$BASE_URL'). Download this script from the server itself."
[[ "$SYNC_MINUTES" =~ ^[0-9]+$ ]] || SYNC_MINUTES=60

KEY_USER=""; CLIENT_NAME=""; SKIP_KEYS=false; AUTO_YES=false; PAYLOAD_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)      KEY_USER="${2:?--user needs a name}"; shift 2 ;;
    --name)      CLIENT_NAME="${2:?--name needs a value}"; shift 2 ;;
    --skip-keys) SKIP_KEYS=true; shift ;;
    --yes|-y)    AUTO_YES=true; shift ;;
    --)          shift; PAYLOAD_ARGS=("$@"); break ;;
    *)           die "Unknown option: $1" ;;
  esac
done

[[ -n "$KEY_USER" ]] || KEY_USER="${DEFAULT_USER:-${SUDO_USER:-root}}"
[[ -n "$CLIENT_NAME" ]] || CLIENT_NAME="$(hostname 2>/dev/null || echo client)"
CLIENT_NAME="${CLIENT_NAME%%.*}"
[[ "$KEY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "'$KEY_USER' is not a valid user name."
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "'$CLIENT_NAME' is not a usable client name (letters, digits, . _ -). Pass --name."
$SKIP_KEYS || id "$KEY_USER" &>/dev/null || die "User '$KEY_USER' does not exist on this machine. Create it first, or pass --user."

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

# --- 1. pin the server's TLS key ---------------------------------------------
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

fetch() {  # fetch <path> <out>
  curl -fsS --proto '=https' --retry 3 --retry-delay 2 --max-time 60 -k --pinnedpubkey "$PIN" \
       -o "$2" "${BASE_URL}$1"
}

install -d -m 755 "$ETC_DIR"
install -d -m 700 "$VAR_DIR"

# --- 2. key sync ----------------------------------------------------------------
if ! $SKIP_KEYS; then
  # A stable random identity, so the server's client list survives renames
  # and address changes. Kept across re-runs.
  CLIENT_ID=""
  [[ -f "$ETC_DIR/client.conf" ]] && CLIENT_ID="$(sed -n 's/^CLIENT_ID=//p' "$ETC_DIR/client.conf" | head -n1)"
  [[ "$CLIENT_ID" =~ ^[a-f0-9]{32}$ ]] || CLIENT_ID="$(openssl rand -hex 16)"

  tmp="$(mktemp)"; fetch /client/sync.sh "$tmp"
  head -n1 "$tmp" | grep -q '^#!' || die "The server did not return the sync script."
  install -m 755 "$tmp" "$SYNC_BIN"; rm -f "$tmp"

  umask 022
  cat > "$ETC_DIR/client.conf" <<EOF
# Written by bootstrap.sh. Nothing here is secret.
SERVER_URL=${BASE_URL}
SERVER_PIN=${PIN}
KEY_USER=${KEY_USER}
CLIENT_NAME=${CLIENT_NAME}
CLIENT_ID=${CLIENT_ID}
EOF

  say "Syncing SSH keys for '$KEY_USER'"
  "$SYNC_BIN" || die "The first key sync failed; nothing was scheduled."

  # --- 3. schedule ---------------------------------------------------------------
  if command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]; then
    cat > "/etc/systemd/system/${UNIT}.service" <<EOF
[Unit]
Description=Sync SSH public keys from the bootstrap server
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SYNC_BIN}
# 75 = the server was unreachable; keys were left unchanged. Not a failure.
SuccessExitStatus=75
EOF
    cat > "/etc/systemd/system/${UNIT}.timer" <<EOF
[Unit]
Description=Sync SSH public keys every ${SYNC_MINUTES} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${SYNC_MINUTES}min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${UNIT}.timer" >/dev/null
    say "Scheduled: systemd timer ${UNIT}.timer, every ${SYNC_MINUTES} minutes"
  elif [[ -d /etc/cron.d ]]; then
    if (( SYNC_MINUTES >= 60 )); then sched="$(( RANDOM % 60 )) */$(( SYNC_MINUTES / 60 )) * * *"
    else sched="*/${SYNC_MINUTES} * * * *"; fi
    printf '%s root %s >/dev/null 2>&1\n' "$sched" "$SYNC_BIN" > "/etc/cron.d/${UNIT}"
    chmod 644 "/etc/cron.d/${UNIT}"
    say "Scheduled: /etc/cron.d/${UNIT}, about every ${SYNC_MINUTES} minutes"
  else
    warn "No systemd and no /etc/cron.d: run $SYNC_BIN on a schedule yourself."
  fi
fi

# --- 4. payload -------------------------------------------------------------------
if [[ "$HAS_PAYLOAD" == 1 ]]; then
  PAYLOAD_DIR="$VAR_DIR/payload"
  rm -rf "$PAYLOAD_DIR"; install -d -m 700 "$PAYLOAD_DIR"
  fetch /files/SHA256SUMS "$PAYLOAD_DIR/SHA256SUMS"
  while read -r _sum file; do
    [[ "$file" =~ ^[A-Za-z0-9._/-]+$ && "$file" != *..* && "$file" != /* ]] || die "Refusing odd path in SHA256SUMS: $file"
    install -d -m 700 "$PAYLOAD_DIR/$(dirname "$file")"
    fetch "/files/$file" "$PAYLOAD_DIR/$file"
  done < "$PAYLOAD_DIR/SHA256SUMS"
  ( cd "$PAYLOAD_DIR" && sha256sum --quiet -c SHA256SUMS ) || die "Checksum mismatch in the payload."
  say "Payload: $(wc -l < "$PAYLOAD_DIR/SHA256SUMS" | tr -d ' ') file(s) downloaded and verified in $PAYLOAD_DIR"
  if [[ -n "$PAYLOAD_ENTRY" ]]; then
    say "Running payload entry: $PAYLOAD_ENTRY ${PAYLOAD_ARGS[*]:-}"
    rc=0
    BOOTSTRAP_URL="$BASE_URL" BOOTSTRAP_PIN="$PIN" BOOTSTRAP_CLIENT="$CLIENT_NAME" BOOTSTRAP_PAYLOAD_DIR="$PAYLOAD_DIR" \
      bash "$PAYLOAD_DIR/$PAYLOAD_ENTRY" ${PAYLOAD_ARGS[@]+"${PAYLOAD_ARGS[@]}"} < /dev/null || rc=$?
    exit "$rc"
  fi
fi

say "Done."
exit 0
}
