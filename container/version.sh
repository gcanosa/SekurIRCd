#!/bin/sh
# The two build arguments the image needs (it is built without .git), worked out the way the Makefile does it -- keep the
# two in step: BUILD_ID is the short commit (+ -dirty), VERSION_SUFFIX is -git.<commit date> unless HEAD is exactly a v* tag.
cd "$(dirname "$0")/.." || exit 1
id=$(git rev-parse --short HEAD 2>/dev/null) || { echo "BUILD_ID=release"; echo "VERSION_SUFFIX="; exit 0; }
git diff --quiet HEAD 2>/dev/null || id=$id-dirty
suffix=
git describe --exact-match --tags --match 'v[0-9]*' HEAD >/dev/null 2>&1 \
  || suffix=-git.$(git log -1 --format=%cd --date=format:%Y%m%d HEAD)
echo "BUILD_ID=$id"
echo "VERSION_SUFFIX=$suffix"
