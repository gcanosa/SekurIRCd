#!/usr/bin/env bash
# Back up everything you need to carry over to a new SekurIRCd version:
# live configs, accounts, K-lines, MOTDs, TLS keys and ChanServ registrations.
# Usage: tools/backup-config.sh [DEST_DIR]     (prompts if omitted)
set -u

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
banner
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -t 1 ]; then
  B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else
  B= R= G= Y= C= D= N=
fi
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$1"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
die()  { printf '%s✘ %s%s\n' "$R" "$1" "$N" >&2; exit 1; }

printf '%s\n  SekurIRCd config backup%s\n%s\n' "$B$C" "$N" "$D$ROOT$N"

# --- destination ---
dest="${1:-}"
if [ -z "$dest" ]; then
  read -r -p "${B}Where should the backup be saved?${N} [/tmp]: " dest
  dest="${dest:-/tmp}"
fi
dest="${dest/#\~/$HOME}"
[ -d "$dest" ] || { read -r -p "$dest doesn't exist. Create it? [Y/n] " a
  case "$a" in [nN]*) die "aborted";; esac; mkdir -p "$dest" || die "can't create $dest"; }
[ -w "$dest" ] || die "$dest is not writable"

# --- collect files (relative to repo root; templates ship with the release, so skipped) ---
cd "$ROOT" || die "cd failed"
patterns=(
  'config/*.toml' 'config/*.json' 'config/*.motd' 'config/*.rules' 'config/*.conf'
  'config/tls/*.pem'
  'services/*.toml' 'services/*.json'
)
files=()
for p in "${patterns[@]}"; do
  for f in $p; do
    [ -f "$f" ] || continue
    case "$f" in *.template.toml) continue;; esac
    files+=("$f")
  done
done
[ ${#files[@]} -gt 0 ] || die "no config files found under $ROOT"

# --- progress ---
printf '\n%sBacking up %d files:%s\n' "$B" "${#files[@]}" "$N"
total=${#files[@]}; i=0; listfile="$(mktemp)"; trap 'rm -f "$listfile"' EXIT
for f in "${files[@]}"; do
  i=$((i+1)); size=$(wc -c <"$f" | tr -d ' ')
  filled=$((i*20/total)); bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((20-filled))" '' | tr ' ' '-')"
  printf '  %s[%s]%s %2d/%d %s%s%s %s(%s bytes)%s\n' "$C" "$bar" "$N" "$i" "$total" "$B" "$f" "$N" "$D" "$size" "$N"
  printf '%s\n' "$f" >>"$listfile"
  case "$f" in config/tls/*|config/accounts.json) warn "contains secrets: keep the archive private";; esac
done

# --- archive ---
out="$dest/sekurircd-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
printf '\n%sCreating archive...%s\n' "$B" "$N"
(umask 077; tar -czf "$out" -T "$listfile") || die "tar failed"
tar -tzf "$out" >/dev/null || die "archive verification failed"

printf '\n%s✔ Done.%s %d files, %s\n  %s%s%s\n' "$B$G" "$N" "$total" "$(du -h "$out" | cut -f1)" "$B" "$out" "$N"
printf '%sRestore with:%s tar -xzf %s -C %s\n' "$D" "$N" "$out" "$ROOT"
