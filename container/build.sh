#!/bin/sh
# Build the image from this checkout:  container/build.sh [image-name]   (default sekurircd:local; ENGINE=docker to use docker)
set -eu
cd "$(dirname "$0")/.."
engine=${ENGINE:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}
img=${1:-sekurircd:local}
exec "$engine" build -f container/Containerfile -t "$img" $(container/version.sh | sed 's/^/--build-arg /') .
