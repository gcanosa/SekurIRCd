#!/bin/sh
# Container entrypoint:  sekurircd-entrypoint ircd | services | stats | makeconf | <any command>
# Everything the admin owns is in $SEKURIRCD_DATA (/data), laid out like the repository root:
#   config/ (sekurircd.toml, protection.toml, TLS, bans, accounts)   services/ (services.toml, the registered channels)
#   stats/ (stats.toml, the database)   logs/ (the ircd's log files)
# The daemons run in the foreground, so the container's own log (podman logs, journalctl) is their log, and SIGTERM stops them.
set -eu
D=${SEKURIRCD_DATA:-/data}
R=/opt/sekurircd
mkdir -p "$D/config" "$D/services" "$D/stats" "$D/logs"
# The *.template.* files are the image's, not the admin's: refresh them so a new image's keys and MOTD show up.
cp -f "$R"/config/*.template.* "$D/config/"
cp -f "$R/services/services.template.toml" "$D/services/"
cp -f "$R/stats/stats.template.toml" "$D/stats/"
cd "$D"
# --pidfile "": a pidfile is no use in a container, and a stale one naming PID 1 (this very process) must not stop a restart.
case "${1:-}" in
  ircd)     shift; exec sekurircd --config "$D/config/sekurircd.toml" --pidfile "" "$@" ;;
  services) shift; cd "$D/services"; exec services --config "$D/services/services.toml" --pidfile "" "$@" ;;
  stats)    shift; cd "$D/stats"; [ $# -gt 0 ] || set -- serve
            exec python3 "$R/stats/netstats.py" -c "$D/stats/stats.toml" "$@" ;;
  makeconf) shift; exec sekurircd --makeconf -c "$D/config/sekurircd.toml" -s "$D/services/services.toml" \
                 --stats "$D/stats/stats.toml" "$@" ;;
  *)        exec "$@" ;;
esac
