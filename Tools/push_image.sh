#!/usr/bin/env bash
# Retry only idempotent registry uploads after known transient failures.
set -euo pipefail
image="${1:?Usage: push_image.sh ghcr.io/owner/image:tag}"
[[ "$image" == ghcr.io/* && "$image" != *[[:space:]]* ]] || exit 2
for attempt in 1 2 3; do
  if output="$(docker push "$image" 2>&1)"; then
    echo "Registry upload completed."
    exit 0
  fi
  if grep -Eiq 'unauthorized|denied|authentication required|insufficient.scope|status.*(401|403)' <<<"$output"; then
    echo 'Registry authentication/permission failure; not retried.' >&2
    exit 1
  fi
  if ! grep -Eiq 'unknown blob|blob upload unknown|connection reset|i/o timeout|context deadline exceeded|unexpected status.*(502|503|504)|server error.*(502|503|504)' <<<"$output"; then
    echo 'Non-retryable registry upload failure; authentication/permission errors are not retried.' >&2
    exit 1
  fi
  echo "Transient layer/upload failure on attempt $attempt of 3." >&2
  if [[ "$attempt" != 3 ]]; then sleep "$((attempt * 5))"; fi
done
echo 'Registry upload retry limit reached.' >&2
exit 1
