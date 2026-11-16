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
# It turns a fresh install into a ready server, one step at a time. Every step
# is safe to run again.
#
#   hostname   set the hostname                      (only with --hostname)
#   timezone   set the timezone                      (only if one is configured)
#   packages   upgrade the system, install the base tools, turn on unattended
#              security upgrades
#   user       make sure the managed user exists and can sudo (with a password)
#   keys       install the key sync and pull the SSH public keys
#   ssh        key-only SSH: no passwords, no root login, only the allowed users
#   power      never sleep: ignore the lid, mask suspend and hibernate
#   journald   keep the system log, capped in size
#   docker     Docker Engine and the compose plugin, with log rotation
#   firewall   UFW: deny incoming except SSH from the local network; ufw-docker
#              so published container ports are closed until allowed
#   payload    download the server's payload, verify it, run its entry script
#
# Options:
#   --user NAME       the managed user: gets the keys, may log in over SSH
#                     (default: the server's default user, else the user who
#                     ran sudo, else root)
#   --name NAME       how this machine appears in the server's client list
#                     (default: its hostname)
#   --hostname NAME   also rename the machine to NAME
#   --timezone ZONE   e.g. Europe/Berlin (overrides TIMEZONE below)
#   --only "a b"      run only these steps        --skip "a b"   leave these out
#   --skip-keys       same as --skip keys
#   --list-steps      print the steps and exit
#   --yes, -y         do not ask questions (pin confirmation, SSH hardening)
#   --                everything after this goes to the payload's entry script
#
set -Eeuo pipefail
# Same patterns and tool output on every machine, whatever its locale.
export LC_ALL=C

# ==============================================================================
# SETTINGS — edit these for your site. Nothing here is secret (this file is
# served to anyone who can reach the server).
# ==============================================================================
STEPS="hostname timezone packages user keys ssh power journald docker firewall payload"

TIMEZONE=""                 # empty: leave the machine's timezone alone
UPGRADE=true                # run a full upgrade in the packages step
BASE_PACKAGES="ca-certificates curl gnupg git sudo openssl openssh-server
  vim htop tmux jq rsync bash-completion python3 bind9-dnsutils iputils-ping
  iproute2 net-tools ethtool systemd-timesyncd unattended-upgrades
  apt-listchanges ufw gettext-base"
EXTRA_PACKAGES=""           # anything else you want on every machine

SSH_ALLOW_USERS=""          # empty: only the managed user may log in over SSH
DISABLE_SLEEP=true          # the power step
JOURNAL_MAX_USE="500M"      # the journald step

ENABLE_UFW=true             # the firewall step
LAN_CIDR=""                 # empty: the network of the default route, detected
UFW_DOCKER_VERSION="251123"
UFW_DOCKER_SHA256="c3e5f0bf6061a3a2e7d7ac06abc80665707d2f4c91e90d76f22e4168863fb472"
# ==============================================================================

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
MARK="Managed by purrbrews-bootstrap"

CURRENT_STEP="start"
WARNINGS=()
say()  { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[bootstrap]\033[0m   %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap] WARNING:\033[0m %s\n' "$*" >&2; WARNINGS+=("[$CURRENT_STEP] $*"); }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m [%s] %s\n' "$CURRENT_STEP" "$*" >&2; exit 1; }
trap 'printf "\033[1;31m[bootstrap] ERROR:\033[0m step \"%s\" failed (line %s). Fix the cause and run the same command again: finished steps are skipped or repeated safely.\n" "$CURRENT_STEP" "$LINENO" >&2' ERR

have_tty()    { { : < /dev/tty; } 2>/dev/null; }
has_systemd() { command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]; }
has_apt()     { command -v apt-get &>/dev/null; }
confirm() {
  $AUTO_YES && return 0
  have_tty || { warn "No terminal to ask '$1' — pass --yes to allow it."; return 1; }
  local reply
  read -r -p "$1 [y/N] " reply < /dev/tty
  [[ "$reply" =~ ^[Yy]$ ]]
}
fetch() {  # fetch <path> <out>
  curl -fsS --proto '=https' --retry 3 --retry-delay 2 --max-time 60 -k --pinnedpubkey "$PIN" \
       -o "$2" "${BASE_URL}$1"
}

# --- options ----------------------------------------------------------------------
KEY_USER=""; CLIENT_NAME=""; NEW_HOSTNAME=""; ONLY=""; SKIP=""; AUTO_YES=false; LIST=false; PAYLOAD_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)       KEY_USER="${2:?--user needs a name}"; shift 2 ;;
    --name)       CLIENT_NAME="${2:?--name needs a value}"; shift 2 ;;
    --hostname)   NEW_HOSTNAME="${2:?--hostname needs a name}"; shift 2 ;;
    --timezone)   TIMEZONE="${2:?--timezone needs a zone}"; shift 2 ;;
    --only)       ONLY="${ONLY} ${2:?--only needs step names}"; shift 2 ;;
    --skip)       SKIP="${SKIP} ${2:?--skip needs step names}"; shift 2 ;;
    --skip-keys)  SKIP="${SKIP} keys"; shift ;;
    --list-steps) LIST=true; shift ;;
    --yes|-y)     AUTO_YES=true; shift ;;
    --)           shift; PAYLOAD_ARGS=("$@"); break ;;
    *)            die "Unknown option: $1" ;;
  esac
done
ONLY="${ONLY//,/ }"; SKIP="${SKIP//,/ }"

if $LIST; then printf '%s\n' $STEPS; exit 0; fi

[[ "$(id -u)" -eq 0 ]] || die "Run as root."
[[ "$BASE_URL" == https://* && "$PIN" == sha256//* ]] \
  || die "This is not run directly. Use the server's one-liner: curl -kfsSL https://<server>:8443/bootstrap.sh | sudo bash -s -- [options]"
[[ "$SYNC_MINUTES" =~ ^[0-9]+$ ]] || SYNC_MINUTES=60

for s in $ONLY $SKIP; do
  [[ " $STEPS " == *" $s "* ]] || die "Unknown step '$s'. Steps: $STEPS"
done
step_enabled() {
  [[ -z "${ONLY// /}" || " $ONLY " == *" $1 "* ]] && [[ " $SKIP " != *" $1 "* ]]
}

[[ -n "$KEY_USER" ]] || KEY_USER="${DEFAULT_USER:-${SUDO_USER:-root}}"
[[ "$KEY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "'$KEY_USER' is not a valid user name."
if [[ -n "$NEW_HOSTNAME" ]]; then
  [[ "$NEW_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || die "'$NEW_HOSTNAME' is not a valid hostname (letters, digits, -)."
  [[ -n "$CLIENT_NAME" ]] || CLIENT_NAME="$NEW_HOSTNAME"
fi
[[ -n "$CLIENT_NAME" ]] || CLIENT_NAME="$(hostname 2>/dev/null || echo client)"
CLIENT_NAME="${CLIENT_NAME%%.*}"
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "'$CLIENT_NAME' is not a usable client name (letters, digits, . _ -). Pass --name."

OS_ID=""; OS_CODENAME=""; OS_PRETTY="unknown"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  OS_ID="$(. /etc/os-release; printf '%s' "${ID:-}")"
  OS_CODENAME="$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")"
  OS_PRETTY="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
fi

user_home() { getent passwd "$1" 2>/dev/null | cut -d: -f6; }

# ==============================================================================
# Steps
# ==============================================================================
step_hostname() {
  [[ -n "$NEW_HOSTNAME" ]] || { say "  no --hostname given: leaving it as $(hostname 2>/dev/null || echo '?')"; return 0; }
  if has_systemd; then hostnamectl set-hostname "$NEW_HOSTNAME"
  else printf '%s\n' "$NEW_HOSTNAME" > /etc/hostname; hostname "$NEW_HOSTNAME" 2>/dev/null || true; fi
  if grep -qE '^127\.0\.1\.1[[:space:]]' /etc/hosts 2>/dev/null; then
    sed -i -E "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t${NEW_HOSTNAME}/" /etc/hosts
  else
    printf '127.0.1.1\t%s\n' "$NEW_HOSTNAME" >> /etc/hosts
  fi
  ok "hostname is $NEW_HOSTNAME"
}

step_timezone() {
  [[ -n "$TIMEZONE" ]] || { say "  no timezone configured: leaving it alone"; return 0; }
  [[ "$TIMEZONE" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$ ]] || die "'$TIMEZONE' does not look like a timezone (e.g. Europe/Berlin)."
  if has_systemd; then
    timedatectl set-timezone "$TIMEZONE" || die "Unknown timezone '$TIMEZONE' (see: timedatectl list-timezones)."
    timedatectl set-ntp true 2>/dev/null || true   # timesyncd may only arrive in the packages step
  else
    [[ -e "/usr/share/zoneinfo/$TIMEZONE" ]] || die "Unknown timezone '$TIMEZONE'."
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
  fi
  ok "timezone is $TIMEZONE"
}

step_packages() {
  has_apt || { warn "No apt-get on this machine ($OS_PRETTY): install the base tools yourself. Skipped."; return 0; }
  export DEBIAN_FRONTEND=noninteractive
  local apt_opts=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  apt-get -q update
  if [[ "$UPGRADE" == true ]]; then apt-get "${apt_opts[@]}" full-upgrade; fi
  # shellcheck disable=SC2086
  apt-get "${apt_opts[@]}" install --no-install-recommends $BASE_PACKAGES $EXTRA_PACKAGES
  has_systemd && timedatectl set-ntp true 2>/dev/null || true

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
// ${MARK}
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  has_systemd && systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "system $([[ "$UPGRADE" == true ]] && echo 'upgraded, ')base packages and unattended security upgrades in place"
}

step_user() {
  if [[ "$KEY_USER" == root ]]; then say "  the managed user is root: nothing to create"; return 0; fi
  if ! id "$KEY_USER" &>/dev/null; then
    if command -v adduser &>/dev/null && adduser --help 2>&1 | grep -q -- '--disabled-password'; then
      adduser --disabled-password --gecos "" "$KEY_USER" >/dev/null
    else
      useradd -m -s /bin/bash "$KEY_USER"
    fi
    say "  created user $KEY_USER"
  fi

  local admin_group=""
  getent group sudo  >/dev/null && admin_group=sudo
  [[ -z "$admin_group" ]] && getent group wheel >/dev/null && admin_group=wheel
  if [[ -n "$admin_group" ]]; then usermod -aG "$admin_group" "$KEY_USER"
  else warn "No sudo or wheel group here: give $KEY_USER admin rights yourself."; fi

  # sudo must ask for a password: SSH is key-only, the password is what gates root.
  local status; status="$(passwd -S "$KEY_USER" 2>/dev/null | awk '{print $2}')"
  if [[ "$status" != P && "$status" != PS ]]; then
    if have_tty && ! $AUTO_YES; then
      say "  set the sudo password for $KEY_USER (SSH stays key-only; this gates root):"
      local tries=0
      until passwd "$KEY_USER" < /dev/tty; do
        tries=$((tries + 1)); [[ $tries -lt 3 ]] || die "Password not set."
      done
    else
      local pw file="/root/purrbrews-bootstrap-password-${KEY_USER}"
      pw="$(openssl rand -base64 18)"
      printf '%s:%s\n' "$KEY_USER" "$pw" | chpasswd
      ( umask 077; printf '%s\n' "$pw" > "$file" )
      warn "Generated a sudo password for $KEY_USER in $file (root only). Store it somewhere safe, then delete the file."
    fi
  fi
  ok "$KEY_USER exists${admin_group:+, in the $admin_group group}, sudo asks for a password"
}

step_keys() {
  id "$KEY_USER" &>/dev/null || die "User '$KEY_USER' does not exist on this machine. Run the user step, or pass --user."
  install -d -m 755 "$ETC_DIR"
  # A stable random identity, so the server's client list survives renames
  # and address changes. Kept across re-runs.
  local client_id="" tmp
  [[ -f "$ETC_DIR/client.conf" ]] && client_id="$(sed -n 's/^CLIENT_ID=//p' "$ETC_DIR/client.conf" | head -n1)"
  [[ "$client_id" =~ ^[a-f0-9]{32}$ ]] || client_id="$(openssl rand -hex 16)"

  tmp="$(mktemp)"; fetch /client/sync.sh "$tmp"
  head -n1 "$tmp" | grep -q '^#!' || die "The server did not return the sync script."
  install -m 755 "$tmp" "$SYNC_BIN"; rm -f "$tmp"

  ( umask 022; cat > "$ETC_DIR/client.conf" <<EOF
# Written by bootstrap.sh. Nothing here is secret.
SERVER_URL=${BASE_URL}
SERVER_PIN=${PIN}
KEY_USER=${KEY_USER}
CLIENT_NAME=${CLIENT_NAME}
CLIENT_ID=${client_id}
EOF
  )

  "$SYNC_BIN" || die "The first key sync failed; nothing was scheduled."

  if has_systemd; then
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
    ok "keys synced for $KEY_USER; systemd timer ${UNIT}.timer, every ${SYNC_MINUTES} minutes"
  elif [[ -d /etc/cron.d ]]; then
    local sched
    if (( SYNC_MINUTES >= 60 )); then sched="$(( RANDOM % 60 )) */$(( SYNC_MINUTES / 60 )) * * *"
    else sched="*/${SYNC_MINUTES} * * * *"; fi
    printf '%s root %s >/dev/null 2>&1\n' "$sched" "$SYNC_BIN" > "/etc/cron.d/${UNIT}"
    chmod 644 "/etc/cron.d/${UNIT}"
    ok "keys synced for $KEY_USER; /etc/cron.d/${UNIT}, about every ${SYNC_MINUTES} minutes"
  else
    warn "No systemd and no /etc/cron.d: run $SYNC_BIN on a schedule yourself."
  fi
}

step_ssh() {
  command -v sshd &>/dev/null || { warn "No SSH server installed: nothing to harden. Skipped."; return 0; }
  local allow="${SSH_ALLOW_USERS:-$KEY_USER}" ak
  ak="$(user_home "$KEY_USER")/.ssh/authorized_keys"
  if ! { [[ -s "$ak" ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$ak"; }; then
    die "$ak has no keys: refusing to turn off password login (you would be locked out). Run the keys step first."
  fi

  local root_login=no
  [[ " $allow " == *" root "* ]] && root_login=prohibit-password
  local conf=/etc/ssh/sshd_config.d/00-purrbrews-bootstrap.conf desired
  desired="$(cat <<EOF
# ${MARK}. Loaded before other drop-ins; the first value wins.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin ${root_login}
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers ${allow}
EOF
)"
  if [[ -f "$conf" && "$(cat "$conf")" == "$desired" ]]; then ok "SSH already hardened (key-only, AllowUsers ${allow})"; return 0; fi

  grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null \
    || { warn "/etc/ssh/sshd_config does not include sshd_config.d/*.conf: add that line, then run --only ssh. Skipped."; return 0; }

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local me="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
    [[ " $allow " == *" $me "* ]] \
      || warn "You are connected over SSH as '$me', who will no longer be allowed to log in (AllowUsers ${allow})."
    confirm "Turn off SSH password login now? First check, from another terminal, that 'ssh ${KEY_USER}@<this machine>' works with your key." \
      || { warn "SSH hardening skipped. Run again with --only ssh when you are ready."; return 0; }
  fi

  install -d -m 755 /etc/ssh/sshd_config.d
  printf '%s\n' "$desired" > "$conf"; chmod 644 "$conf"
  install -d -m 755 /run/sshd 2>/dev/null || true
  if ! sshd -t; then rm -f "$conf"; die "The SSH configuration test failed: change reverted."; fi
  if has_systemd; then
    local unit=ssh; systemctl cat ssh.service &>/dev/null || unit=sshd
    systemctl enable "$unit" >/dev/null 2>&1 || true
    systemctl reload-or-restart "$unit"
  else
    warn "No systemd: restart the SSH server yourself to apply the new settings."
  fi
  ok "SSH: key-only, root login ${root_login}, AllowUsers ${allow}"
}

step_power() {
  [[ "$DISABLE_SLEEP" == true ]] || { say "  DISABLE_SLEEP is off: skipped"; return 0; }
  has_systemd || { warn "No systemd: cannot change sleep behaviour. Skipped."; return 0; }
  install -d /etc/systemd/logind.conf.d
  cat > /etc/systemd/logind.conf.d/50-purrbrews-bootstrap.conf <<EOF
# ${MARK}: a server must not sleep when a lid closes.
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
HandleSuspendKey=ignore
HandleHibernateKey=ignore
IdleAction=ignore
EOF
  systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1 || true
  # A HUP makes logind re-read its settings without ending sessions.
  systemctl kill -s HUP systemd-logind 2>/dev/null || true
  ok "lid close ignored, suspend and hibernate masked"
}

step_journald() {
  has_systemd || { warn "No systemd: no journal to configure. Skipped."; return 0; }
  [[ "$JOURNAL_MAX_USE" =~ ^[0-9]+[KMGT]$ ]] || die "JOURNAL_MAX_USE must look like 500M or 2G."
  install -d /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/50-purrbrews-bootstrap.conf <<EOF
# ${MARK}
[Journal]
Storage=persistent
SystemMaxUse=${JOURNAL_MAX_USE}
EOF
  systemctl restart systemd-journald
  ok "journal kept on disk, capped at ${JOURNAL_MAX_USE}"
}

step_docker() {
  if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null; then
    case "$OS_ID" in
      debian|ubuntu) ;;
      *) warn "Docker is installed from Docker's own apt repository, which this step only knows for Debian and Ubuntu (this is $OS_PRETTY). Skipped."; return 0 ;;
    esac
    export DEBIAN_FRONTEND=noninteractive
    # Remove distro packages that conflict with Docker's own.
    local p
    for p in docker.io docker-doc docker-compose podman-docker containerd runc; do
      if dpkg -s "$p" &>/dev/null; then apt-get -y -q remove "$p"; fi
    done
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    local suite="$OS_CODENAME"
    if [[ -z "$suite" ]] || ! curl -fsS -m 10 -o /dev/null "https://download.docker.com/linux/${OS_ID}/dists/${suite}/Release"; then
      [[ "$OS_ID" == debian ]] || die "Docker's repository has no '${suite}' suite for ${OS_ID}."
      warn "Docker's repository has no '${suite}' suite yet: using bookworm."
      suite=bookworm
    fi
    rm -f /etc/apt/sources.list.d/docker.list
    cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${OS_ID}
Suites: ${suite}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    apt-get -q update
    apt-get -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi

  # Log rotation: without it container logs grow until the disk is full.
  command -v jq &>/dev/null || { has_apt && apt-get -y -q install jq >/dev/null; }
  install -d /etc/docker
  local daemon=/etc/docker/daemon.json restart=false
  local want='{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"live-restore":true}'
  if [[ -f "$daemon" ]]; then
    local merged
    merged="$(jq -S --argjson w "$want" '. * $w' "$daemon")" || die "$daemon is not valid JSON: fix or remove it."
    if [[ "$merged" != "$(jq -S . "$daemon")" ]]; then printf '%s\n' "$merged" > "$daemon"; restart=true; fi
  else
    jq -S . <<<"$want" > "$daemon"; restart=true
  fi

  if has_systemd; then
    systemctl enable --now docker containerd >/dev/null
    if $restart; then systemctl restart docker; fi
    docker info >/dev/null 2>&1 || die "The Docker daemon is not responding: see 'journalctl -u docker'."
  else
    warn "No systemd: start the Docker daemon yourself."
  fi
  ok "$(docker --version | cut -d, -f1), compose $(docker compose version --short 2>/dev/null || echo '?'), container logs rotated"
}

step_firewall() {
  [[ "$ENABLE_UFW" == true ]] || { say "  ENABLE_UFW is off: skipped"; return 0; }
  command -v ufw &>/dev/null || { warn "ufw is not installed (the packages step installs it). Skipped."; return 0; }

  local lan="$LAN_CIDR"
  if [[ -z "$lan" ]]; then
    local dev
    dev="$(ip -4 route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    [[ -n "$dev" ]] && lan="$(ip -4 route show dev "$dev" scope link 2>/dev/null | awk '$1 ~ /\// {print $1; exit}')"
  fi
  [[ "$lan" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] \
    || { warn "Could not work out the local network. Set LAN_CIDR in client/bootstrap.sh on the server, then run --only firewall. Skipped (firewall left as it was)."; return 0; }

  # Additive only: never 'ufw reset', which would wipe rules added since.
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow from "$lan" to any port 22 proto tcp comment 'bootstrap: ssh from the local network' >/dev/null
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    ufw allow from "${SSH_CONNECTION%% *}" to any port 22 proto tcp comment 'bootstrap: ssh session at setup' >/dev/null
  fi
  ufw --force enable >/dev/null

  if command -v docker &>/dev/null && ! docker info >/dev/null 2>&1; then
    ok "UFW on: SSH from ${lan} only"
    warn "Docker is installed but its daemon is not running, so ufw-docker was skipped. Start Docker, then run --only firewall."
  elif command -v docker &>/dev/null; then
    local bin=/usr/local/bin/ufw-docker have="" tmp
    [[ -f "$bin" ]] && have="$(sha256sum "$bin" | cut -d' ' -f1)"
    if [[ "$have" != "$UFW_DOCKER_SHA256" ]]; then
      tmp="$(mktemp)"
      curl -fsSL -o "$tmp" "https://raw.githubusercontent.com/chaifeng/ufw-docker/${UFW_DOCKER_VERSION}/ufw-docker"
      [[ "$(sha256sum "$tmp" | cut -d' ' -f1)" == "$UFW_DOCKER_SHA256" ]] \
        || { rm -f "$tmp"; die "ufw-docker ${UFW_DOCKER_VERSION} does not match its expected checksum: not installing."; }
      install -m 755 "$tmp" "$bin"; rm -f "$tmp"
    fi
    # --docker-subnets: only Docker's own networks bypass the rules. Without it
    # ufw-docker lets every private address through, which is the whole LAN.
    if ! ufw-docker check --docker-subnets >/dev/null 2>&1; then
      ufw-docker install --docker-subnets
      has_systemd && systemctl restart ufw
    fi
    ok "UFW on: SSH from ${lan} only; container ports stay closed until 'ufw-docker allow'"
  else
    ok "UFW on: SSH from ${lan} only"
    warn "Docker is not installed, so ufw-docker was skipped. Run --only firewall after the docker step."
  fi
}

PAYLOAD_RC=0
step_payload() {
  [[ "$HAS_PAYLOAD" == 1 ]] || { say "  the server has no payload: nothing to do"; return 0; }
  install -d -m 700 "$VAR_DIR"
  local dir="$VAR_DIR/payload" _sum file
  rm -rf "$dir"; install -d -m 700 "$dir"
  fetch /files/SHA256SUMS "$dir/SHA256SUMS"
  while read -r _sum file; do
    [[ "$file" =~ ^[A-Za-z0-9._/-]+$ && "$file" != *..* && "$file" != /* ]] || die "Refusing odd path in SHA256SUMS: $file"
    install -d -m 700 "$dir/$(dirname "$file")"
    fetch "/files/$file" "$dir/$file"
  done < "$dir/SHA256SUMS"
  ( cd "$dir" && sha256sum --quiet -c SHA256SUMS ) || die "Checksum mismatch in the payload."
  ok "payload: $(wc -l < "$dir/SHA256SUMS" | tr -d ' ') file(s) downloaded and verified in $dir"

  # A readable copy for the person who ran this, in their home folder. The
  # verified original above stays root-only, and the entry script runs from
  # there: root never executes anything out of a user-writable folder.
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && id "$SUDO_USER" &>/dev/null; then
    local home copy
    home="$(user_home "$SUDO_USER")"
    if [[ -n "$home" && -d "$home" ]]; then
      copy="$home/purrbrews-bootstrap-payload"
      rm -rf -- "$copy"
      mkdir -m 755 -- "$copy"
      cp -R "$dir"/. "$copy"/
      chown -R -h "$SUDO_USER:$(id -gn "$SUDO_USER")" "$copy"
      chmod -R u+rwX,go+rX,go-w "$copy"
      ok "your copy of the payload: $copy (replaced on every run)"
    fi
  fi

  if [[ -n "$PAYLOAD_ENTRY" ]]; then
    say "  running payload entry: $PAYLOAD_ENTRY ${PAYLOAD_ARGS[*]:-}"
    BOOTSTRAP_URL="$BASE_URL" BOOTSTRAP_PIN="$PIN" BOOTSTRAP_CLIENT="$CLIENT_NAME" BOOTSTRAP_PAYLOAD_DIR="$dir" \
      bash "$dir/$PAYLOAD_ENTRY" ${PAYLOAD_ARGS[@]+"${PAYLOAD_ARGS[@]}"} < /dev/null || PAYLOAD_RC=$?
    if (( PAYLOAD_RC != 0 )); then warn "The payload's entry script exited with status $PAYLOAD_RC."; fi
  fi
}

# ==============================================================================
# Run
# ==============================================================================
say "Setting up '$CLIENT_NAME' ($OS_PRETTY) for user '$KEY_USER' from $BASE_URL"
for s in $STEPS; do
  if step_enabled "$s"; then
    CURRENT_STEP="$s"
    say "→ $s"
    "step_$s"
  fi
done
CURRENT_STEP="done"

if [[ ${#WARNINGS[@]} -gt 0 ]]; then
  printf '\n\033[1;33m[bootstrap] Finished with %s warning(s):\033[0m\n' "${#WARNINGS[@]}" >&2
  printf '  - %s\n' "${WARNINGS[@]}" >&2
else
  say "Done. No warnings."
fi
exit "$PAYLOAD_RC"
