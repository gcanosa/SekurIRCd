#!/usr/bin/env bash
# Show the changelog for the latest release tag, then everything committed since it.
# Usage: tools/changelog.sh
set -eu
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
banner

if [ -t 1 ]; then
  B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else
  B= G= Y= C= D= N=
fi


last=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null) || { echo "no release tags" >&2; exit 1; }
prev=$(git describe --tags --abbrev=0 --match 'v*' "$last^" 2>/dev/null || true)
# Ask the tty itself: tput/stty on a pipe (inside $(...)) always says 80.
W=$({ stty size </dev/tty | cut -d" " -f2; } 2>/dev/null); [ "${W:-0}" -gt 0 ] 2>/dev/null || W=${COLUMNS:-80}
[ -t 1 ] || W=${COLUMNS:-80}

# Print commits as "  hash subject ....... timestamp", timestamp flush right.
show() {
  git --no-pager log --no-merges '--date=format:%Y-%m-%d %H:%M' --format='%h%x09%ad%x09%s' "$1" |
  while IFS=$'\t' read -r h d s; do
    room=$(( W - ${#d} - ${#h} - 5 ))
    [ ${#s} -le $room ] || s="${s:0:room-1}…"
    printf '  %s%s%s %s%*s%s%s\n' "$Y" "$h" "$N" "$s" $(( room - ${#s} + 2 )) "" "$D" "$d$N"
  done
}

printf '%s\n' "${B}${G}Release $last:${N}"
show "${prev:+$prev..}$last"

printf '\n%s\n' "${B}${C}Additions from the last release onwards:${N}"
n=$(git rev-list --count "$last..HEAD")
if [ "$n" -eq 0 ]; then echo "  (nothing)"; else show "$last..HEAD"; fi
# Pushed vs local-only, so you know what's not on the remote yet.
if up=$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null); then
  u=$(git rev-list --count "$up..HEAD"); [ "$u" -eq 0 ] || printf '  %s\n' "${Y}($u commit(s) not pushed to $up)${N}"
fi
