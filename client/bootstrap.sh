#!/usr/bin/env bash
#
# client/bootstrap.sh — the installer a new machine runs.
#
# This file is NOT built into the server image. The server reads it live from
# its client/ folder, so it can change without a new image or a restart: edit
# it (or `git pull`) on the server machine and the next client gets the new
# version. Machines never fetch it directly; the server's /bootstrap.sh
# wrapper verifies the server's TLS key first, then downloads and runs this
# with what it learned in PB_* variables (see "handed over" below).
#
# What it does:
#   1. Installs the key-sync script and its settings, and syncs the SSH public
#      keys into the chosen user's authorized_keys (a managed block; lines you
#      added by hand are left alone).
#   2. Schedules the sync (systemd timer, or cron where there is no systemd).
#   3. If the server carries a payload, downloads it, checks it against
#      SHA256SUMS, leaves a readable copy in the home folder of the user who
#      ran sudo, and runs its entry script when one is configured.
#
# Options:
#   --user NAME     whose authorized_keys to manage (default: the server's
#                   default user, else the user who ran sudo, else root)
#   --name NAME     how this machine appears in the server's client list
#                   (default: its hostname)
#   --skip-keys     do not set up key sync (payload only)
#   --yes, -y       (handled by the wrapper: do not ask to confirm the pin)
#   --              everything after this goes to the payload's entry script
#
set -Eeuo pipefail
# Same patterns and tool output on every machine, whatever its locale.
export LC_ALL=C

# --- handed over by the wrapper -----------------------------------------------
BASE_URL="${PB_BASE_URL:-}"              # the server, as this client reaches it
PIN="${PB_SERVER_PIN:-}"                 # its TLS pin, already verified
SYNC_MINUTES="${PB_SYNC_MINUTES:-60}"
DEFAULT_USER="${PB_DEFAULT_USER:-}"
HAS_PAYLOAD="${PB_HAS_PAYLOAD:-0}"
PAYLOAD_ENTRY="${PB_PAYLOAD_ENTRY:-}"

ETC_DIR="/etc/purrbrews-bootstrap"
VAR_DIR="/var/lib/purrbrews-bootstrap"
SYNC_BIN="/usr/local/sbin/purrbrews-bootstrap-sync"
UNIT="purrbrews-bootstrap-sync"

say()  { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "Run as root."
[[ "$BASE_URL" == https://* && "$PIN" == sha256//* ]] \
  || die "This is not run directly. Use the server's one-liner: curl -kfsSL https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]"
[[ "$SYNC_MINUTES" =~ ^[0-9]+$ ]] || SYNC_MINUTES=60

KEY_USER=""; CLIENT_NAME=""; SKIP_KEYS=false; PAYLOAD_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)      KEY_USER="${2:?--user needs a name}"; shift 2 ;;
    --name)      CLIENT_NAME="${2:?--name needs a value}"; shift 2 ;;
    --skip-keys) SKIP_KEYS=true; shift ;;
    --yes|-y)    shift ;;
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

fetch() {  # fetch <path> <out>
  curl -fsS --proto '=https' --retry 3 --retry-delay 2 --max-time 60 -k --pinnedpubkey "$PIN" \
       -o "$2" "${BASE_URL}$1"
}

install -d -m 755 "$ETC_DIR"
install -d -m 700 "$VAR_DIR"

# --- 1. key sync ----------------------------------------------------------------
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

  # --- 2. schedule ---------------------------------------------------------------
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

# --- 3. payload -------------------------------------------------------------------
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

  # A readable copy for the person who ran this, in their home folder. The
  # verified original above stays root-only, and the entry script runs from
  # there: root never executes anything out of a user-writable folder.
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && id "$SUDO_USER" &>/dev/null; then
    user_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -n "$user_home" && -d "$user_home" ]]; then
      USER_COPY="$user_home/purrbrews-bootstrap-payload"
      rm -rf -- "$USER_COPY"
      mkdir -m 755 -- "$USER_COPY"
      cp -R "$PAYLOAD_DIR"/. "$USER_COPY"/
      chown -R -h "$SUDO_USER:$(id -gn "$SUDO_USER")" "$USER_COPY"
      chmod -R u+rwX,go+rX,go-w "$USER_COPY"
      say "Your copy of the payload: $USER_COPY (replaced on every run)"
    fi
  fi
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
