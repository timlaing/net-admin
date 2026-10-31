#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -euo pipefail
export NETADMIN_ADDON=1
export NETADMIN_DATA_DIR=/data
# Import legacy values before deleting their retired Supervisor options. The
# migration emits only fixed option names, never connection values or secrets.
netadmin_retired_options="$(bashio::addon.options | python3 -m netadmin.addon_options)"
for netadmin_option in $netadmin_retired_options; do
  bashio::addon.option "$netadmin_option"
done
# The in-app Settings page is the sole owner of saved service connections.
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
