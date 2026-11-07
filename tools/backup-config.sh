#!/usr/bin/env bash
# Back up everything you need to carry over to a new SekurIRCd version:
# live configs, accounts (and their rotating backups), K-lines, MOTDs, TLS keys and ChanServ registrations.
# Usage: tools/backup-config.sh [DEST_DIR]               back up (prompts if omitted)
#        tools/backup-config.sh --restore [ARCHIVE|DIR]  restore a backup (picks from DIR, default /tmp)
# A restore first backs up the current files, then validates the result with tools/confcheck.py
# (which runs the daemons' own --check) and rolls back if it fails.
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

mode=backup
[ "${1:-}" = "--restore" ] && { mode=restore; shift; }
printf '%s\n  SekurIRCd config %s%s\n%s\n' "$B$C" "$mode" "$N" "$D$ROOT$N"

# --- destination / source dir ---
pick_dir() {  # $1 = prompt; sets $dest
  if [ -z "$dest" ]; then
    read -r -p "${B}$1${N} [/tmp]: " dest
    dest="${dest:-/tmp}"
  fi
  dest="${dest/#\~/$HOME}"
}

# --- backup: sets $out ---
backup() {
  [ -d "$dest" ] || { read -r -p "$dest doesn't exist. Create it? [Y/n] " a
    case "$a" in [nN]*) die "aborted";; esac; mkdir -p "$dest" || die "can't create $dest"; }
  [ -w "$dest" ] || die "$dest is not writable"

  # collect files (relative to repo root; templates ship with the release, so skipped)
  cd "$ROOT" || die "cd failed"
  local patterns=(
    'config/*.toml' 'config/*.json' 'config/*.motd' 'config/*.rules' 'config/*.conf'
    'config/tls/*.pem'
    'services/*.toml' 'services/*.json'
    'config/*.json.bak*' 'services/*.json.bak*'
  )
  local files=() p f
  for p in "${patterns[@]}"; do
    for f in $p; do
      [ -f "$f" ] || continue
      case "$f" in *.template.toml) continue;; esac
      files+=("$f")
    done
  done
  [ ${#files[@]} -gt 0 ] || die "no config files found under $ROOT"

  printf '\n%sBacking up %d files:%s\n' "$B" "${#files[@]}" "$N"
  local total=${#files[@]} i=0 size filled bar listfile
  listfile="$(mktemp)"
  for f in "${files[@]}"; do
    i=$((i+1)); size=$(wc -c <"$f" | tr -d ' ')
    filled=$((i*20/total)); bar="$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' "$((20-filled))" '' | tr ' ' '-')"
    printf '  %s[%s]%s %2d/%d %s%s%s %s(%s bytes)%s\n' "$C" "$bar" "$N" "$i" "$total" "$B" "$f" "$N" "$D" "$size" "$N"
    printf '%s\n' "$f" >>"$listfile"
    case "$f" in config/tls/*|config/accounts.json) warn "contains secrets: keep the archive private";; esac
  done

  out="$dest/sekurircd-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  printf '\n%sCreating archive...%s\n' "$B" "$N"
  (umask 077; tar -czf "$out" -T "$listfile") || { rm -f "$listfile"; die "tar failed"; }
  rm -f "$listfile"
  tar -tzf "$out" >/dev/null || die "archive verification failed"
  printf '\n%s✔ Done.%s %d files, %s\n  %s%s%s\n' "$B$G" "$N" "$total" "$(du -h "$out" | cut -f1)" "$B" "$out" "$N"
}

if [ "$mode" = backup ]; then
  dest="${1:-}"; pick_dir "Where should the backup be saved?"
  backup
  printf '%sRestore with:%s %s --restore %s\n' "$D" "$N" "$0" "$out"
  exit 0
fi

# ===================== restore =====================
arc="${1:-}"; arc="${arc/#\~/$HOME}"
if [ ! -f "$arc" ]; then
  dest="$arc"; pick_dir "Where are the backups?"
  [ -d "$dest" ] || die "$dest is not a directory"
  # names carry YYYYmmdd-HHMMSS, so a reverse name sort is newest first
  list=(); while IFS= read -r f; do list+=("$f"); done < <(ls -1 "$dest"/sekurircd-backup-*.tar.gz 2>/dev/null | sort -r)
  [ ${#list[@]} -gt 0 ] || die "no sekurircd-backup-*.tar.gz in $dest"
  printf '\n%sBackups in %s:%s\n' "$B" "$dest" "$N"
  for i in "${!list[@]}"; do
    printf '  %s%2d)%s %s %s(%s)%s\n' "$C" $((i+1)) "$N" "$(basename "${list[i]}")" "$D" "$(du -h "${list[i]}" | cut -f1)" "$N"
  done
  read -r -p "${B}Restore which?${N} [1]: " n; n="${n:-1}"
  case "$n" in *[!0-9]*|'') die "not a number: $n";; esac
  [ "$n" -ge 1 ] && [ "$n" -le ${#list[@]} ] || die "no backup #$n"
  arc="${list[n-1]}"
fi
arc="$(cd "$(dirname "$arc")" && pwd)/$(basename "$arc")"
members=(); while IFS= read -r f; do members+=("$f"); done < <(tar -tzf "$arc") || die "can't read $arc"
[ ${#members[@]} -gt 0 ] || die "$arc is empty"

# Only what backup() writes: refuse absolute paths, .. and anything outside config/ and services/.
for f in "${members[@]}"; do
  case "$f" in /*|*..*) die "unsafe path in archive: $f";; config/*|services/*) ;; *) die "unexpected path in archive: $f";; esac
done

cd "$ROOT" || die "cd failed"
printf '\n%sRestoring %s:%s\n' "$B" "$(basename "$arc")" "$N"
new=(); changed=0
for f in "${members[@]}"; do
  case "$f" in */) continue;; esac  # directory entries (hand-made archives)
  if [ ! -e "$f" ]; then printf '  %snew%s      %s\n' "$G" "$N" "$f"; new+=("$f"); changed=1
  elif tar -xOzf "$arc" "$f" | cmp -s - "$f"; then printf '  %ssame%s     %s\n' "$D" "$N" "$f"
  else printf '  %schanged%s  %s\n' "$Y" "$N" "$f"; changed=1; fi
done
[ $changed = 1 ] || { ok "every file already matches the backup; nothing to do"; exit 0; }

if ./sekurircd status 2>/dev/null | grep -q ': *running'; then
  warn "the ircd/services are running: they read the .json data (accounts, K-lines, ChanServ) at start"
  warn "and rewrite it on the next change, so restart them right after this restore (./sekurircd restart)"
fi
read -r -p "${B}Overwrite the files marked changed?${N} [y/N] " a
case "$a" in [yY]*) ;; *) die "aborted";; esac

# Safety net: back up what is live now, next to the archive being restored.
dest="$(dirname "$arc")"; backup; safety="$out"; cd "$ROOT" || die "cd failed"

rollback() {
  warn "rolling back to $safety"
  local f; for f in ${new[@]+"${new[@]}"}; do rm -f "$f"; done
  tar -xzf "$safety" || die "ROLLBACK FAILED: restore by hand with: tar -xzf $safety -C $ROOT"
  die "restore undone; your files are as they were"
}

printf '\n%sExtracting...%s\n' "$B" "$N"
tar -xzf "$arc" || rollback
ok "extracted ${#members[@]} files"

if command -v python3 >/dev/null 2>&1; then
  printf '\n%sChecking the restored config...%s\n' "$B" "$N"
  python3 tools/confcheck.py -q --no-banner || {
    printf '%sThe restored config has errors.%s Old keys from an older version can often be fixed with tools/confcheck.py --fix --write.\n' "$R" "$N"
    read -r -p "${B}Keep it anyway (and fix it yourself)?${N} [y/N] " a
    case "$a" in [yY]*) warn "kept; fix it before the next REHASH/restart";; *) rollback;; esac
  }
else
  warn "python3 not found: config not validated (run bin/sekurircd --check yourself)"
fi

printf '\n%s✔ Restored%s from %s\n' "$B$G" "$N" "$arc"
printf '%sUndo with:%s %s --restore %s\n' "$D" "$N" "$0" "$safety"
printf '%sApply with /REHASH (configs, MOTDs) or ./sekurircd restart (accounts, K-lines, ChanServ, TLS keys).%s\n' "$D" "$N"
