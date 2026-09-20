#!/bin/sh
# Emit web/changelog.json from git tags: [{tag, date, changes:[subject,...]}], newest first.
# Needs full history (actions/checkout fetch-depth: 0).
cd "$(dirname "$0")/../.." || exit 1
out=web/changelog.json
esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }
printf '[' > "$out"
prev=""; first=1
for tag in $(git tag --sort=-v:refname); do
  older=$(git tag --sort=-v:refname | sed -n "/^$tag\$/{n;p;}")
  range=${older:+$older..}$tag
  [ $first = 1 ] || printf ',' >> "$out"; first=0
  printf '{"tag":"%s","date":"%s","changes":[' "$tag" "$(git log -1 --format=%cs "$tag")" >> "$out"
  git log --no-merges --format=%s "$range" | esc | awk 'NR>1{printf ","} {printf "\"%s\"", $0}' >> "$out"
  printf ']}' >> "$out"
done
printf ']\n' >> "$out"
