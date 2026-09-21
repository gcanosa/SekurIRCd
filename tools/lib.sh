# Shared helpers for tools/*.sh. Source it, then call `banner` first thing:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"; banner
# The version in the banner is read from the "powered by SekurIRCd vX" line of config/ircd.motd (kept in sync per release).
# Clear the screen and show the SekurIRCd banner, centered to the terminal width (colour only on a tty).
banner() {
  local art=(
'  ____          _                  ___  ____    ____      _ '
' / ___|   ___  | | __ _   _  _ __ |_ _||  _ \  / ___|  __| |'
' \___ \  / _ \ | |/ /| | | || '"'"'__| | | | |_) || |     / _` |'
'  ___) ||  __/ |   < | |_| || |    | | |  _ < | |___ | (_| |'
' |____/  \___| |_|\_\ \__,_||_|   |___||_| \_\ \____| \__,_|')
  local col=(96 96 94 94 34) sub
  local ver url="https://gcanosa.github.io/SekurIRCd/"
  ver=$(sed -n 's/.*powered by \(SekurIRCd v[0-9.]*\).*/\1/p' "$(dirname "${BASH_SOURCE[0]}")/../config/ircd.motd" | head -1)
  sub=("small tools  -  secure by default  -  no nonsense" "${ver:-SekurIRCd}" "$url")
  local w=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)} tty=0 i pad line
  [ -t 1 ] && { tty=1; printf '\e[H\e[2J\e[3J'; }
  echo
  for i in "${!art[@]}"; do
    line=${art[i]}; pad=$(( (w - ${#line}) / 2 )); [ $pad -lt 0 ] && pad=0
    if [ $tty = 1 ]; then printf '%*s\e[%sm%s\e[0m\n' $pad '' "${col[i]}" "$line"
    else printf '%*s%s\n' $pad '' "$line"; fi
  done
  echo
  for line in "${sub[@]}"; do
    pad=$(( (w - ${#line}) / 2 )); [ $pad -lt 0 ] && pad=0
    if [ $tty = 1 ]; then printf '%*s\e[90m%s\e[0m\n' $pad '' "$line"; else printf '%*s%s\n' $pad '' "$line"; fi
  done
  echo
}
