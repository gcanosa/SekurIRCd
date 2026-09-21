# Shared helpers for tools/*.sh. Source it, then call `banner` first thing:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"; banner
# The banner (and its version line) comes from config/ircd.motd, so bumping the MOTD updates every script.
# Clear the screen and show the SekurNet banner (top of config/ircd.motd, up to the first ==== rule).
# mIRC codes -> ANSI (\002 bold, \003NN colour, \017 reset); stripped when not a tty.
banner() {
  [ -t 1 ] && printf '\e[H\e[2J\e[3J'
  sed '/=====/,$d' "$(dirname "${BASH_SOURCE[0]}")/../config/ircd.motd" | perl -pe '
    if (-t STDOUT) {
      my %c=(2=>34,11=>96,12=>94,14=>90,15=>37);
      s/\003(\d\d?)/"\e[".($c{$1+0}||39)."m"/ge; s/\002/\e[1m/g; s/\017/\e[0m/g;
    } else { s/\003\d\d?|[\002\017]//g }
    s/\n/\e[0m\n/ if -t STDOUT;'
}
