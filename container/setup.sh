#!/usr/bin/env bash
# SekurIRCd in rootless podman: a guided install, then day-to-day control.
#   container/setup.sh install [--data DIR] [--image IMAGE] [--build]    first install (the default command)
#   container/setup.sh upgrade | status | start|stop|restart [ircd|services|stats] | logs [ircd|services|stats]
#   container/setup.sh rehash | wizard | hash-password | backup [FILE] | uninstall | help
# Needs podman 5.0 or newer (Quadlet pods are not used, but its unit files are) and a systemd user session. The config, logs and
# databases live in one directory (default ~/sekurircd); the containers are systemd user units, so they start at boot.
# This one file is all you need: the unit files are written from here. See container/README.md.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
UNITDIR=${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd
DATA=${SEKURIRCD_DATA:-$HOME/sekurircd}
IMAGE=${SEKURIRCD_IMAGE:-ghcr.io/gcanosa/sekurircd:latest}
CONTAINERS=(ircd services stats)

if [ -f "$here/../tools/lib.sh" ]; then source "$here/../tools/lib.sh"; banner; else echo; echo "  SekurIRCd in podman"; echo; fi
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then G=$'\033[32m' R=$'\033[31m' Y=$'\033[33m' B=$'\033[1m' D=$'\033[2m' N=$'\033[0m'; else G= R= Y= B= D= N=; fi
step() { echo; echo "${B}== $*${N}"; }
ok()   { echo " ${G}+${N} $*"; }
note() { echo "   ${D}$*${N}"; }
warn() { echo " ${Y}!${N} $*"; }
die()  { echo " ${R}x${N} $*" >&2; exit 1; }
# Prompts read standard input (a terminal, or answers piped in), and take the default at the end of input.
ask()  { local a=; read -r -p "$1 [$2]: " a || true; echo "${a:-$2}"; }
yes()  { local a=; read -r -p "$1 [$([ "$2" = y ] && echo Y/n || echo y/N)]: " a || true; a=${a:-$2}; [ "${a:0:1}" = y ] || [ "${a:0:1}" = Y ]; }

unit_file() { echo "$UNITDIR/sekurircd-$1.container"; }
# Where an installed setup keeps things: read back from the unit files, so every command works from any directory.
load_state() {
  local f; f=$(unit_file ircd)
  [ -f "$f" ] || die "not installed yet: container/setup.sh install"
  IMAGE=$(sed -n 's/^Image=//p' "$f"); DATA=$(sed -n 's/^Volume=\(.*\):\/data:z$/\1/p' "$f")
}
toml_val() { # toml_val SECTION KEY FILE -> the value, quotes stripped
  awk -v s="[$1]" -v k="$2" '/^\[/ { on = ($0 == s) } on && $1 == k && $2 == "=" { gsub(/"/, "", $3); print $3; exit }' "$3"
}

# One Quadlet unit per daemon, all on the host network: clients keep their real addresses (bans, limits, cloaks and DNSBL all
# depend on them) and nothing needs publishing. The container runs as you (keep-id, mapped to the image's uid 1000), so the data directory stays yours.
# Volume :z, not :Z: on SELinux hosts :Z gives each container its own private label, so the second one to start locks the first out.
unit() { # unit NAME DESCRIPTION CONDITION-FILE-IN-DATA
  cat <<EOF
[Unit]
Description=$2
After=network-online.target$([ "$1" != ircd ] && echo " sekurircd-ircd.service")
Wants=network-online.target
${3:+ConditionPathExists=$DATA/$3}

[Container]
Image=$IMAGE
ContainerName=sekurircd-$1
Exec=$1
Network=host
UserNS=keep-id:uid=1000,gid=1000
Volume=$DATA:/data:z
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL

[Service]
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
}

preflight() {
  step "Checking this machine"
  [ "$(id -u)" != 0 ] || die "run this as your own user, not root: the containers are rootless"
  command -v podman >/dev/null || die "podman is not installed (apt install podman / dnf install podman)"
  local v; v=$(podman version --format '{{.Client.Version}}' 2>/dev/null)
  [ "${v%%.*}" -ge 5 ] 2>/dev/null || die "podman $v is too old: this needs 5.0 or newer (container/compose.yaml works with older podman and Docker)"
  ok "podman $v"
  systemctl --user show-environment >/dev/null 2>&1 || die "no systemd user session here (log in with a full session, e.g. ssh or the console); container/compose.yaml needs none"
  ok "systemd user session"
  case $(uname -m) in x86_64|aarch64|arm64) ok "$(uname -m)" ;; *) die "no image for $(uname -m): 64-bit x86 and arm only" ;; esac
}

get_image() {
  if [ "$build" = 1 ]; then
    step "Building the image from this checkout"
    [ -x "$here/build.sh" ] && [ -f "$here/../Makefile" ] || die "--build needs the whole repository: git clone https://github.com/gcanosa/SekurIRCd.git"
    ENGINE=podman "$here/build.sh" localhost/sekurircd:local || die "the build failed"
    IMAGE=localhost/sekurircd:local
  elif [[ $IMAGE == localhost/* ]]; then
    podman image exists "$IMAGE" || die "$IMAGE is a local image and there is none: container/setup.sh install --build"
  else
    step "Pulling $IMAGE"
    podman pull "$IMAGE" || die "could not pull $IMAGE (not published yet? from a checkout: container/setup.sh install --build)"
  fi
  ok "image ready"
}

run_wizard() {
  podman run -i$([ -t 0 ] && echo t) --rm --userns=keep-id:uid=1000,gid=1000 -v "$DATA:/data:z" "$IMAGE" makeconf || die "the wizard did not finish"
  [ -s "$DATA/config/sekurircd.toml" ] || die "no $DATA/config/sekurircd.toml was written"
}

write_units() {
  mkdir -p "$UNITDIR"
  unit ircd     "SekurIRCd IRC server"                        ""                      >"$(unit_file ircd)"
  unit services "SekurIRCd services (NickServ + ChanServ)"    services/services.toml >"$(unit_file services)"
  unit stats    "SekurIRCd network stats panel"               stats/stats.toml        >"$(unit_file stats)"
  systemctl --user daemon-reload
  systemctl --user cat sekurircd-ircd.service >/dev/null 2>&1 \
    || die "podman's unit generator rejected $UNITDIR (try: /usr/lib/podman/quadlet -dryrun -user, or /usr/libexec/podman/quadlet)"
}

cmd_install() {
  build=0
  while [ $# -gt 0 ]; do case $1 in
    --data) DATA=${2:?--data DIR}; shift ;; --image) IMAGE=${2:?--image IMAGE}; shift ;; --build) build=1 ;;
    *) die "unknown option $1" ;; esac; shift; done
  preflight
  step "Where should SekurIRCd keep its config, logs and data?"
  DATA=$(ask "Directory" "$DATA"); DATA=${DATA/#\~/$HOME}
  mkdir -p "$DATA" && DATA=$(cd "$DATA" && pwd) || die "cannot create $DATA"
  ok "$DATA"
  get_image

  if [ -s "$DATA/config/sekurircd.toml" ]; then
    step "Config"; ok "found $DATA/config/sekurircd.toml, keeping it ($(basename "$0") wizard runs the questions again)"
  else
    step "Configuring: a few questions, then it writes the config and checks it"
    run_wizard
  fi

  step "Installing the systemd units"
  write_units
  systemctl --user start sekurircd-ircd sekurircd-services sekurircd-stats
  ok "started: ircd, and services and the stats panel when you configured them"
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != yes ]; then
    loginctl enable-linger "$USER" 2>/dev/null && ok "linger on: it starts at boot and survives you logging out" \
      || warn "could not turn on linger: run  sudo loginctl enable-linger $USER  or it stops when you log out"
  fi
  verify
}

verify() {
  step "Checking it answers"
  local cfg=$DATA/config/sekurircd.toml port host i
  port=$(toml_val server port "$cfg"); host=$(toml_val server bind "$cfg")
  [ "$host" = 0.0.0.0 ] || [ -z "$host" ] && host=127.0.0.1
  for i in $(seq 20); do
    if (exec 3<>"/dev/tcp/$host/${port:-6667}") 2>/dev/null; then ok "the ircd listens on $host:${port:-6667}"; break; fi
    [ "$i" = 20 ] && { warn "nothing on $host:${port:-6667} after 10 s; see: $(basename "$0") logs"; break; }
    sleep 0.5
  done
  local tls; tls=$(toml_val tls port "$cfg")
  echo
  echo "${B}Next${N}"
  echo "  1. open the ports in your firewall: ${port:-6667}/tcp${tls:+, $tls/tcp (TLS)}  (e.g. ufw allow ${port:-6667}/tcp)"
  echo "  2. connect:  /server <this machine> ${tls:-${port:-6667}}  and /OPER with the login you made in the wizard"
  echo "  3. check real addresses: from ANOTHER machine, connect and /WHOIS yourself: it must show that machine's address"
  echo "  4. the MOTD:  $DATA/config/ircd.motd      the log:  $DATA/logs/      back it up:  $(basename "$0") backup"
  echo "  5. an update later:  $(basename "$0") upgrade"
}

names() { if [ -n "${1:-}" ]; then echo "$1"; else echo "${CONTAINERS[@]}"; fi; }
svc() { local v=$1 n; shift; for n in $(names "${1:-}"); do systemctl --user "$v" "sekurircd-$n"; done; }

cmd_status() {
  load_state; echo "  image: $IMAGE"; echo "  data:  $DATA"; echo
  local n s
  for n in "${CONTAINERS[@]}"; do
    s=$(systemctl --user is-active "sekurircd-$n" 2>/dev/null)
    if [ "$s" = active ]; then ok "$n: running"
    elif [ "$n" = services ] && [ ! -f "$DATA/services/services.toml" ]; then note "services: not configured (a leaf, or you said no in the wizard)"
    elif [ "$n" = stats ] && [ ! -f "$DATA/stats/stats.toml" ]; then note "stats: not configured"
    else echo " ${R}x${N} $n: $s"; fi
  done
  podman exec sekurircd-ircd sekurircd --version 2>/dev/null | sed 's/^/  /'
}

cmd_upgrade() {
  load_state
  local before after; before=$(podman image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
  case $IMAGE in
    localhost/*) step "Rebuilding $IMAGE"; ENGINE=podman "$here/build.sh" "${IMAGE#localhost/}" || die "the build failed" ;;
    *)           step "Pulling $IMAGE"; podman pull "$IMAGE" || die "could not pull $IMAGE" ;;
  esac
  after=$(podman image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null)
  [ "$before" != "$after" ] || { ok "already up to date"; return; }
  step "Restarting"
  systemctl --user restart sekurircd-services sekurircd-stats 2>/dev/null; ok "services and the stats panel restarted (nobody is disconnected)"
  if yes "Restart the ircd now? It disconnects everyone; always-on sessions come back" n; then systemctl --user restart sekurircd-ircd && ok "ircd restarted"
  else note "still running the old version: $(basename "$0") restart ircd  when you are ready"; fi
}

cmd_backup() {
  load_state
  local out=${1:-$HOME/sekurircd-backup-$(date +%Y%m%d-%H%M).tar.gz}
  ( umask 077; tar -czf "$out" -C "$DATA" --exclude=logs --exclude='*.template.*' config services stats ) || die "backup failed"
  ok "$out  ($(du -h "$out" | cut -f1)) -- it holds password hashes and your TLS key: keep it private"
}

cmd_uninstall() {
  load_state
  yes "Stop SekurIRCd and remove its units? (your data in $DATA stays)" n || exit 0
  local n; for n in "${CONTAINERS[@]}"; do systemctl --user stop "sekurircd-$n" 2>/dev/null; rm -f "$(unit_file "$n")"; done
  systemctl --user daemon-reload; ok "removed; the data is still in $DATA, the image in podman (podman rmi $IMAGE)"
}

cmd_help() { sed -n '2,4p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

cmd=${1:-install}; [ $# -gt 0 ] && shift
case $cmd in
  install)        cmd_install "$@" ;;
  upgrade)        cmd_upgrade ;;
  status)         cmd_status ;;
  start|stop|restart) load_state; svc "$cmd" "${1:-}" ;;
  logs)           load_state; exec journalctl --user -u "sekurircd-${1:-ircd}" -n 100 -f ;;
  rehash)         load_state; podman kill --signal HUP sekurircd-ircd >/dev/null && ok "ircd rehashed"; podman kill --signal HUP sekurircd-services >/dev/null 2>&1 && ok "services reloaded" ;;
  wizard)         load_state; run_wizard; ok "written; apply it: $(basename "$0") restart" ;;
  hash-password)  load_state; exec podman run -i$([ -t 0 ] && echo t) --rm "$IMAGE" sekurircd --hash-password ;;
  backup)         cmd_backup "$@" ;;
  uninstall)      cmd_uninstall ;;
  help|-h|--help) cmd_help ;;
  *)              cmd_help; exit 2 ;;
esac
