#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -euo pipefail
export NETADMIN_ADDON=1
export NETADMIN_DATA_DIR=/data
NETADMIN_DHCP_BACKEND="$(bashio::config 'dhcp_backend')"
NETADMIN_DNS_SERVER="$(bashio::config 'dns_server')"
NETADMIN_DNS_ZONES="$(bashio::config 'dns_zones')"
NETADMIN_DHCP_AGENT_URL="$(bashio::config 'dhcp_agent_url')"
NETADMIN_RADIUS_AGENT_URL="$(bashio::config 'radius_agent_url')"
export NETADMIN_DHCP_BACKEND NETADMIN_DNS_SERVER NETADMIN_DNS_ZONES NETADMIN_DHCP_AGENT_URL NETADMIN_RADIUS_AGENT_URL
# Legacy Supervisor options seed connections; the in-app Settings page owns saved values.
netadmin_env_file="${NETADMIN_ENV_FILE:-/config/netadmin.env}"
if [[ -r "$netadmin_env_file" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$netadmin_env_file"
  set +a
fi
# Authentication policy belongs to the Supervisor option, not connection reloads.
NETADMIN_INGRESS_REQUIRE_LOGIN="$(bashio::config 'ingress_require_login')"
export NETADMIN_INGRESS_REQUIRE_LOGIN
NETADMIN_SUPERVISOR_VERSION="$(bashio::info.supervisor || true)"
export NETADMIN_SUPERVISOR_VERSION
# S6 manages the process; no Gunicorn management socket is needed under /root.
exec gunicorn --no-control-socket --bind 0.0.0.0:8099 --workers 1 --access-logfile - netadmin.wsgi:app
