#!/bin/sh
# ISC cannot run without a subnet on a listening interface. Stay available for
# first UI configuration and acknowledge every subsequent agent restart.
set -eu
mkdir -p /run/netadmin
child=''
reload=false
recover=false
failed_configuration=''
# Poll child liveness for a finite number of seconds.
wait_for_exit() {
  remaining="$1"
  while kill -0 "$child" 2>/dev/null; do
    [ "$remaining" -gt 0 ] || return 1
    sleep 1
    remaining=$((remaining - 1))
  done
}
# Terminate the current DHCP child with bounded TERM and KILL waits.
stop() {
  if [ -n "$child" ]; then
    kill -TERM "$child" 2>/dev/null || true
    if ! wait_for_exit 5; then
      kill -KILL "$child" 2>/dev/null || true
      if ! wait_for_exit 2; then
        echo 'ISC DHCP did not exit after TERM and KILL.' >&2
        return 1
      fi
    fi
    # Reap only after the process has exited; never wait indefinitely.
    wait "$child" 2>/dev/null || true
  fi
}
trap 'stop; exit 0' TERM INT
trap 'reload=true' HUP
/usr/local/bin/entrypoint-dhcp.sh -t -cf /etc/dhcp/dhcpd.conf
# Validate configuration and start DHCP only when subnets exist.
start() {
  # Installer-owned configuration starts empty. Agent-created subnets are in
  # this file; the managed include contains only host reservations.
  if grep -Eq '^[[:space:]]*subnet[[:space:]]+[0-9]' /etc/dhcp/dhcpd.conf; then
    dhcpd -4 -f -d -cf /etc/dhcp/dhcpd.conf -lf /var/lib/dhcp/dhcpd.leases "$DHCP_INTERFACE" &
    child=$!
    sleep 1
    kill -0 "$child" 2>/dev/null
  else
    child=''
    echo 'ISC DHCP is waiting for its first subnet in NetAdmin.'
  fi
}
start
# Track configuration changes so reloads restart only when necessary.
signature() { cksum /etc/dhcp/dhcpd.conf /etc/dhcp/netadmin-reservations.conf; }
while true; do
  if [ "$reload" = true ]; then
    reload=false
    request="$(cat /run/netadmin/request)"
    failed_configuration="$(signature)"
    if stop; then
      child=''
      if start; then
        result=ok
        recover=false
      else
        result=failed
        child=''
        recover=true
      fi
    else
      result=failed
      recover=false
    fi
    printf '%s %s\n' "$request" "$result" > /run/netadmin/result.tmp
    mv /run/netadmin/result.tmp /run/netadmin/result
  fi
  # The agent restores files after a failed acknowledgement. Wait for that
  # restoration before restarting the previous configuration.
  if [ "$recover" = true ] && [ "$(signature)" != "$failed_configuration" ]; then
    if start; then recover=false; fi
  fi
  if [ -n "$child" ] && ! kill -0 "$child" 2>/dev/null; then
    echo 'ISC DHCP exited unexpectedly.' >&2
    exit 1
  fi
  sleep 1 &
  wait $! || true
done
