#!/bin/sh
# ISC cannot run without a subnet on a listening interface. Stay available for
# first UI configuration and acknowledge every subsequent agent restart.
set -eu
mkdir -p /run/netadmin
child=''
reload=false
recover=false
failed_configuration=''
stop() {
  if [ -n "$child" ]; then
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
}
trap 'stop; exit 0' TERM INT
trap 'reload=true' HUP
/usr/local/bin/entrypoint-dhcp.sh -t -cf /etc/dhcp/dhcpd.conf
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
signature() { cksum /etc/dhcp/dhcpd.conf /etc/dhcp/netadmin-reservations.conf; }
while true; do
  if [ "$reload" = true ]; then
    reload=false
    request="$(cat /run/netadmin/request)"
    stop
    child=''
    failed_configuration="$(signature)"
    if start; then
      result=ok
      recover=false
    else
      result=failed
      child=''
      recover=true
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
