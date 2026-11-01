#!/usr/bin/env bash
# Keep PID 1 stable while certificate operations replace the EAP TLS context.
# USR1 is reserved for the authenticated agent's certificate activation protocol.
set -uo pipefail
certs=/etc/raddb/certs
control="$certs/.netadmin-control"
request="$certs/.netadmin-restart-request"
result="$certs/.netadmin-restart-result"
child=""
rotate=false
stop() {
  rm -f "$control"
  if [[ -n "$child" ]]; then
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  exit 0
}
trap stop TERM INT
trap 'rotate=true' USR1
trap '[[ -z "$child" ]] || kill -HUP "$child" 2>/dev/null || true' HUP
umask 077
printf '1\n' > "$control"
rm -f "$result"
pending=""
while true; do
  radiusd -f "$@" &
  child=$!
  if [[ -n "$pending" ]]; then
    # A failed instantiate exits immediately; do not acknowledge that activation.
    sleep 2
    if kill -0 "$child" 2>/dev/null; then
      printf '%s\n' "$pending" > "$result.tmp"
      mv "$result.tmp" "$result"
    fi
    pending=""
  fi
  status=0
  while kill -0 "$child" 2>/dev/null; do
    wait "$child" || status=$?
    if [[ "$rotate" == true ]]; then break; fi
  done
  if [[ "$rotate" != true ]]; then
    rm -f "$control"
    exit "$status"
  fi
  rotate=false
  pending="$(cat "$request" 2>/dev/null || true)"
  kill -TERM "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
done
