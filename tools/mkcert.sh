#!/usr/bin/env bash
# Get a trusted (Let's Encrypt) TLS certificate for your IRC domain, install it where
# sekurircd.toml's [tls] expects it, set up auto-renewal, and rehash the running ircd.
# Uses acme.sh (pure POSIX sh; Linux, macOS, *BSD) with a DNS-01 challenge, so port 80
# does not need to be open.
#
# Usage: tools/mkcert.sh --domain irc.example.org [options]
#   --domain NAME    certificate name; repeat for extra names (first = primary). Required.
#   --dns PLUGIN     acme.sh DNS plugin (default dns_duckdns). Credentials go in that plugin's
#                    env vars, e.g. DuckDNS_Token=... or CF_Token=... (see acme.sh's dnsapi docs).
#   --webroot DIR    use HTTP-01 against this web root instead of DNS (port 80 must be open)
#   --email ADDR     Let's Encrypt expiry notices
#   --config FILE    sekurircd.toml (default config/sekurircd.toml)
#   --pidfile FILE   daemon pidfile (default $SEKURIRCD_PIDFILE or ./sekurircd.pid)
#   --staging        use the Let's Encrypt staging CA (untrusted certs; for testing)
#   --dry-run        show what would happen, change nothing
set -eu

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else G= Y= R= N=; fi
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$1"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
die()  { printf '%s✘ %s%s\n' "$R" "$1" "$N" >&2; exit 1; }
usage() { sed -n '2,/^set -eu/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }

domains=() dns=dns_duckdns webroot= email= staging= dry=
config="$ROOT/config/sekurircd.toml"
pidfile="${SEKURIRCD_PIDFILE:-$PWD/sekurircd.pid}"
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)  [ $# -ge 2 ] || usage; domains+=("$2"); shift 2;;
    --dns)     [ $# -ge 2 ] || usage; dns=$2; shift 2;;
    --webroot) [ $# -ge 2 ] || usage; webroot=$2; shift 2;;
    --email)   [ $# -ge 2 ] || usage; email=$2; shift 2;;
    --config)  [ $# -ge 2 ] || usage; config=$2; shift 2;;
    --pidfile) [ $# -ge 2 ] || usage; pidfile=$2; shift 2;;
    --staging) staging=1; shift;;
    --dry-run) dry=1; shift;;
    -h|--help) usage;;
    *) die "unknown option: $1";;
  esac
done
[ ${#domains[@]} -gt 0 ] || { warn "--domain is required"; usage; }
for d in "${domains[@]}"; do
  case "$d" in *[!A-Za-z0-9.*-]*|'') die "invalid domain: $d";; esac
done
[ -f "$config" ] || die "config not found: $config"
config="$(cd "$(dirname "$config")" && pwd)/$(basename "$config")"
cfgdir=$(dirname "$config")
run() { if [ -n "$dry" ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

# --- where does [tls] want the files? (paths are relative to the config's directory) ---
tomlval() { # key within [tls]
  awk -v k="$1" '/^\[/{s=($0=="[tls]")} s && $1==k && $2=="=" {v=$0; sub(/^[^=]*=[ \t]*/,"",v); sub(/[ \t]*#.*$/,"",v); gsub(/"/,"",v); print v; exit}' "$config"
}
grep -q '^\[tls\]' "$config" || die "no [tls] section in $config (copy it from config/sekurircd.template.toml first)"
cert=$(tomlval cert_file); key=$(tomlval key_file)
cert=${cert:-tls/cert.pem}; key=${key:-tls/key.pem}
case "$cert" in /*) ;; *) cert="$cfgdir/$cert";; esac
case "$key"  in /*) ;; *) key="$cfgdir/$key";; esac
ok "cert -> $cert"; ok "key  -> $key"

# --- fetch acme.sh if needed ---
ACME_HOME="${ACME_HOME:-$HOME/.acme.sh}"
ACME="$ACME_HOME/acme.sh"
if [ ! -x "$ACME" ]; then
  url=https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz
  warn "installing acme.sh from $url"
  if [ -z "$dry" ]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/mkcert.XXXXXX"); trap 'rm -rf "$tmp"' EXIT
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$url" -o "$tmp/a.tgz"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$tmp/a.tgz" "$url"
    else die "need curl or wget"; fi
    tar -xzf "$tmp/a.tgz" -C "$tmp" || die "could not unpack acme.sh"
    # the installer must run from inside its own checkout (it copies the dnsapi/ plugins too)
    (cd "$tmp"/acme.sh-* && sh ./acme.sh --install --home "$ACME_HOME" ${email:+--accountemail "$email"}) >/dev/null 2>&1 \
      || die "acme.sh install failed (run it by hand: https://github.com/acmesh-official/acme.sh)"
  else echo "  [dry-run] download + install acme.sh into $ACME_HOME"; fi
fi
command -v openssl >/dev/null 2>&1 || die "openssl not found"

# --- DNS credentials: explain, and ask if missing ---
if [ -z "$webroot" ] && [ -z "$dry" ]; then
  if [ "$dns" = dns_duckdns ]; then
    if [ -z "${DuckDNS_Token:-}" ] && ! grep -qs '^SAVED_DuckDNS_Token=' "$ACME_HOME/account.conf"; then
      cat >&2 <<EOF

  Let's Encrypt must verify you own ${domains[0]}. This script proves it by creating a
  temporary DNS TXT record through the DuckDNS API, which needs your account token
  (shown at the top of https://www.duckdns.org after you log in).
  To skip this prompt next time:   export DuckDNS_Token=your-token
  acme.sh saves it in $ACME_HOME/account.conf (mode 600) so renewals run unattended.
  The token is never printed or written anywhere else by this script.

EOF
      [ -t 0 ] || die "DuckDNS_Token is not set and there is no terminal to ask on"
      read -rs -p "  DuckDNS token (input hidden): " DuckDNS_Token; echo
      [ -n "$DuckDNS_Token" ] || die "no token given"
      export DuckDNS_Token
    fi
  else
    warn "using $dns: set that plugin's credentials as env vars first (see https://github.com/acmesh-official/acme.sh/wiki/dnsapi for the names), e.g. export CF_Token=..."
  fi
fi

# --- issue ---
args=(--issue --server letsencrypt)
for d in "${domains[@]}"; do args+=(-d "$d"); done
if [ -n "$webroot" ]; then args+=(-w "$webroot"); else args+=(--dns "$dns"); fi
[ -z "$staging" ] || args+=(--staging)
if [ -n "$dry" ]; then echo "  [dry-run] $ACME ${args[*]}"
else
  set +e; "$ACME" "${args[@]}"; rc=$?; set -e
  [ $rc -eq 0 ] || [ $rc -eq 2 ] || die "issuing failed (acme.sh exit $rc; 2 would mean 'not due for renewal')"
fi

# --- install + reload hook (also what acme.sh's cron renewal runs) ---
reload="if [ -r '$pidfile' ] && kill -0 \"\$(cat '$pidfile')\" 2>/dev/null; then kill -HUP \"\$(cat '$pidfile')\"; fi"
run mkdir -p "$(dirname "$cert")" "$(dirname "$key")"
[ -n "$dry" ] || { [ ! -f "$cert" ] || cp -p "$cert" "$cert.bak"; [ ! -f "$key" ] || cp -p "$key" "$key.bak"; }
umask 077
iargs=(--install-cert --ecc -d "${domains[0]}" --key-file "$key" --fullchain-file "$cert" --reloadcmd "$reload")
if [ -n "$dry" ]; then echo "  [dry-run] $ACME ${iargs[*]}"
else "$ACME" "${iargs[@]}" >/dev/null || die "install-cert failed"; chmod 600 "$key"; fi
ok "certificate installed (old ones kept as *.bak)"

# --- make sure [tls] is enabled (sed -> temp -> mv: GNU and BSD sed disagree on -i) ---
if [ "$(tomlval enabled)" != true ]; then
  if [ -n "$dry" ]; then echo "  [dry-run] set enabled = true in [tls]"
  else
    cp -p "$config" "$config.bak"
    awk '/^\[/{s=($0=="[tls]")} s && $1=="enabled" && $2=="=" {print "enabled = true"; next} {print}' "$config" > "$config.new" \
      && mv "$config.new" "$config"
    ok "[tls] enabled in $config (backup: $config.bak)"
  fi
else ok "[tls] already enabled in $config"; fi

# --- rehash now ---
if [ -n "$dry" ]; then echo "  [dry-run] rehash via $pidfile"
elif [ -r "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
  kill -HUP "$(cat "$pidfile")" && ok "rehash sent to pid $(cat "$pidfile") (new connections use the new cert)"
else warn "ircd not running (no live pid in $pidfile); start it, or /REHASH once it is"; fi

# --- web chat needs the [websocket] listener over TLS: check, never edit ---
wsval() { awk -v k="$1" '/^\[/{s=($0=="[websocket]")} s && $1==k && $2=="=" {v=$0; sub(/^[^=]*=[ \t]*/,"",v); sub(/[ \t]*#.*$/,"",v); print v; exit}' "$config"; }
if [ "$(wsval enabled)" = true ] && [ "$(wsval tls)" = true ]; then
  ok "[websocket] enabled with tls = true (port $(wsval port)): browser clients can use wss://${domains[0]}:$(wsval port)"
else
  warn "web chat needs this in $config, then /REHASH (no restart):"
  printf '      [websocket]\n      enabled = true\n      port = 12155\n      tls = true\n      allowed_origins = ["https://gcanosa.github.io"]\n'
fi

command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -q acme.sh \
  && ok "auto-renewal cron entry present" \
  || warn "no acme.sh cron entry found; add: 0 3 * * * \"$ACME\" --cron --home \"$ACME_HOME\" >/dev/null"
[ -z "$staging" ] || warn "STAGING certificate: browsers will NOT trust it. Re-run without --staging."
