#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -euo pipefail
export NETADMIN_ADDON=1
if [[ -r /config/netadmin.env ]]; then
  set -a
  # shellcheck source=/dev/null
  source /config/netadmin.env
  set +a
fi
export NETADMIN_DATA_DIR=/data
NETADMIN_DHCP_BACKEND="$(bashio::config 'dhcp_backend')"
NETADMIN_DNS_SERVER="$(bashio::config 'dns_server')"
NETADMIN_DNS_ZONES="$(bashio::config 'dns_zones')"
NETADMIN_DHCP_AGENT_URL="$(bashio::config 'dhcp_agent_url')"
NETADMIN_RADIUS_AGENT_URL="$(bashio::config 'radius_agent_url')"
export NETADMIN_DHCP_BACKEND NETADMIN_DNS_SERVER NETADMIN_DNS_ZONES NETADMIN_DHCP_AGENT_URL NETADMIN_RADIUS_AGENT_URL
# S6 manages the process; no Gunicorn management socket is needed under /root.
exec gunicorn --no-control-socket --bind 0.0.0.0:8099 --workers 1 --access-logfile - netadmin.wsgi:app
