#!/usr/bin/env bash
# A successful authenticated push does not prove a fresh host can pull the image.
set -euo pipefail
version="${1:?Usage: check_public_images.sh VERSION}"
owner="${IMAGE_OWNER:-timlaing}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || exit 2
[[ "$owner" =~ ^[a-z0-9][a-z0-9-]*$ ]] || exit 2
anonymous_config="$(mktemp -d)"
trap 'rm -rf "$anonymous_config"' EXIT
for suffix in '' '-dhcp-agent' '-dns-agent' '-radius-agent' '-ca-agent' '-ca-runtime' '-dns' '-dhcp' '-dhcp-kea' '-radius'; do
  image="ghcr.io/$owner/netadmin$suffix:$version"
  if ! docker --config "$anonymous_config" manifest inspect "$image" >/dev/null; then
    echo "Anonymous pull verification failed for $image." >&2
    echo 'Set the GHCR package visibility to Public, then rerun this job. See docs/releasing.md.' >&2
    exit 1
  fi
  echo "Anonymous manifest access verified: $image"
done
