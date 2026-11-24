#!/usr/bin/env bash
# End-to-end check of the image, the way an admin uses it:  container/smoke.sh IMAGE   (ENGINE=podman|docker, default podman)
#   1. the config wizard, answered on stdin, writes files its own --check accepts
#   2. the ircd and services start from them on the host network, a client registers and finds NickServ
#   3. a restart works, SIGHUP rehashes, and a stop is graceful (the daemons are PID 1, so SIGTERM must reach them)
# The wizard's answers are in the order it asks: when a question is added to tools/makeconf.py, add its answer here.
set -euo pipefail
img=${1:?usage: container/smoke.sh IMAGE}
engine=${ENGINE:-podman}
port=$((20000 + RANDOM % 20000)) tls=$((port + 1)) link=$((port + 2)) panel=$((port + 3))
name=sekurircd-smoke-$$
data=$(mktemp -d)
if [ "$engine" = podman ]; then who=(--userns=keep-id:uid=1000,gid=1000); else who=(--user "$(id -u):$(id -g)"); fi
opts=("${who[@]}" --security-opt label=disable -v "$data:/data")
ok() { printf ' \033[32m+\033[0m %s\n' "$*"; }
die() { printf ' \033[31mx\033[0m %s\n' "$*" >&2; for c in ircd svc stats; do echo "--- $c"; "$engine" logs --tail 40 "$name-$c" 2>&1 || true; done; exit 1; }
trap '"$engine" rm -f "$name-ircd" "$name-svc" "$name-stats" >/dev/null 2>&1 || true; rm -rf "$data"' EXIT

answers=(
  ''                              # this machine runs: 1 (the ircd and services together)
  irc.smoke.test SmokeNet ''      # server name, network, server id
  127.0.0.1 "$port" ''            # bind, plaintext port, IPv6 (n)
  ''                              # leaf (n)
  '' "$tls" '' ''                 # TLS (y), TLS port, certificate, key
  ''                              # websocket (n)
  '' '' '' '' ''                  # cloak, protection bundle, klines, user modes, oper modes
  '' '' '' '' ''                  # protection: max connections, per IP, connect flood, line flood, exempt
  n '' ''                         # DNSBL (n, no DNS in a test), spam, proxy scanner
  '' ''                           # auto-join, history lines
  '' '' smokepw smokepw '' ''     # operator: add (y), name, password twice, hosts, another (n)
  '' ''                           # oper auto-join, debug channel
  '' ''                           # admin email, log level
  '' "$link" '' '' '' '' ''       # services (y), link port, name, other links, NickServ, enforce, admins
  '' '' ''                        # account expiry days, channel expiry days, founder rank
  y "$panel" '' '' '' '' smokepw smokepw   # stats panel (y), port, bind, hostname, public viewer, admin name, password twice
  '' ''                           # write the files (y), make a self-signed certificate (y)
)
printf '%s\n' "${answers[@]}" | "$engine" run -i --rm "${opts[@]}" "$img" makeconf --no-banner >"$data/wizard.log" 2>&1 \
  || { cat "$data/wizard.log"; die "the config wizard failed"; }
for f in config/sekurircd.toml services/services.toml config/tls/cert.pem config/tls/key.pem stats/stats.toml; do
  [ -s "$data/$f" ] || { cat "$data/wizard.log"; die "the wizard did not write $f"; }
done
ok "the wizard wrote the config, services.toml and a TLS certificate and stats.toml"

# A client, run in a container of its own because on podman-machine the host network is the VM's, not this machine's.
client() { "$engine" run -i --rm --network host "$img" python3 - "$port" "$@"; }  # argv[1] is the ircd port, argv[2] what the caller adds
probe() { client <<'PY'
import socket, sys, time
port = int(sys.argv[1]); end = time.time() + 30
def read_until(s, want):
    buf = b""
    while want not in buf and time.time() < end:
        try: buf += s.recv(4096)
        except socket.timeout: pass
    return buf
while True:
    try:
        s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(3)
        s.sendall(b"NICK smoke\r\nUSER smoke 0 * :smoke\r\n")
        welcome = read_until(s, b" 001 smoke ")
        s.sendall(b"WHOIS NickServ\r\n")
        out = read_until(s, b" 318 smoke NickServ "); s.close()
        if b" 001 smoke " in welcome and b" 311 smoke NickServ " in out: print("registered, and NickServ is linked"); break
    except OSError: pass
    if time.time() > end: sys.exit("no registration or no NickServ in time")
    time.sleep(0.5)
PY
}

"$engine" run -d --name "$name-ircd" --network host "${opts[@]}" "$img" ircd >/dev/null
"$engine" run -d --name "$name-svc" --network host "${opts[@]}" "$img" services >/dev/null
"$engine" run -d --name "$name-stats" --network host "${opts[@]}" "$img" stats >/dev/null
probe >/dev/null || die "a client could not register, or services never linked"
ok "ircd and services run, a client registered and found NickServ"
client "$panel" >/dev/null <<'PY' || die "the stats panel did not answer"
import sys, time, urllib.request, urllib.error
end = time.time() + 30
while True:
    try: urllib.request.urlopen("http://127.0.0.1:%s/" % sys.argv[2], timeout=3); break
    except urllib.error.HTTPError: break  # any HTTP answer, a login page included, means it is serving
    except OSError:
        if time.time() > end: sys.exit("no answer from the panel")
        time.sleep(0.5)
PY
ok "the stats panel serves"

"$engine" restart -t 10 "$name-ircd" "$name-svc" "$name-stats" >/dev/null
probe >/dev/null || die "after a restart, no client registration or services link"
ok "both containers restart cleanly (no stale pidfile in the way)"

"$engine" kill --signal HUP "$name-ircd" >/dev/null
for _ in $(seq 20); do "$engine" logs "$name-ircd" 2>&1 | grep -q "rehashed config" && break; sleep 0.5; done
"$engine" logs "$name-ircd" 2>&1 | grep -q "rehashed config" || die "SIGHUP did not rehash the config"
ok "SIGHUP rehashes the config"

start=$SECONDS
"$engine" stop -t 10 "$name-ircd" "$name-svc" "$name-stats" >/dev/null
code=$("$engine" inspect --format '{{.State.ExitCode}}' "$name-ircd" "$name-svc" "$name-stats" | tr '\n' ' ')
[ "$code" = "0 0 0 " ] && [ $((SECONDS - start)) -lt 8 ] || die "the daemons did not stop on SIGTERM (exit codes: $code, took $((SECONDS - start))s)"
ok "SIGTERM stops all three at once (exit 0)"
