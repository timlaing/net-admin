#!/usr/bin/env bash
# Smoke-test the Home Assistant add-on image.
#
# Runs the image as an unconfigured add-on (NETADMIN_ADDON=1, no environment
# file) and verifies the first-run wizard is reachable only through ingress,
# then verifies the wizard locks itself once an environment file exists.
set -euo pipefail
image="${1:?Usage: smoke_addon.sh <image>}"
name="netadmin-addon-smoke-${RANDOM}"
volume="${name}-config"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 100 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Exercise the packaged migration and real Bashio option-removal functions.
# Only the Supervisor API transport is synthetic; no live options are touched.
docker run --rm -i --network none --entrypoint /bin/bash "$image" -s <<'BASH'
set -euo pipefail
source /usr/lib/bashio/bashio.sh
export NETADMIN_ENV_FILE=/tmp/migration/netadmin.env
mkdir -p /tmp/migration/bin
printf '%s\n' 'NETADMIN_DNS_SERVER=saved.example' > "$NETADMIN_ENV_FILE"
printf '%s\n' '{"ingress_require_login":true,"dhcp_backend":"kea","dns_server":"legacy.example","dns_zones":""}' > /tmp/migration/options.json
function bashio::api.supervisor() {
  case "$1 $2" in
    'GET /addons/self/info') jq '{options:.}' /tmp/migration/options.json ;;
    'GET /addons/self/options/config') jq '{ingress_require_login:.ingress_require_login}' /tmp/migration/options.json ;;
    'GET /info') printf '%s\n' '{"supervisor":"2026.10.5"}' ;;
    'POST /addons/self/options')
      grep -q 'NETADMIN_DHCP_BACKEND=kea' "$NETADMIN_ENV_FILE" || return 1
      printf '%s' "$3" | jq '.options' > /tmp/migration/options.json
      ;;
    *) return 1 ;;
  esac
}
cat > /tmp/migration/bin/gunicorn <<'STUB'
#!/bin/sh
printf '%s|%s|%s|%s' "$NETADMIN_DHCP_BACKEND" "$NETADMIN_DNS_SERVER" "$NETADMIN_DNS_ZONES" "$NETADMIN_INGRESS_REQUIRE_LOGIN"
STUB
chmod 755 /tmp/migration/bin/gunicorn
export PATH="/tmp/migration/bin:$PATH"
result="$(source /run.sh)"
[[ "$result" == 'kea|saved.example||true' ]]
[[ "$(jq -c . /tmp/migration/options.json)" == '{"ingress_require_login":true}' ]]
first="$(cat "$NETADMIN_ENV_FILE")"
second="$(source /run.sh)"
[[ "$second" == "$result" ]]
[[ "$(cat "$NETADMIN_ENV_FILE")" == "$first" ]]
echo 'Packaged legacy-option import, cleanup and repeat-start checks passed'
BASH

docker volume create "$volume" >/dev/null
# Give only these disposable, network-isolated test containers a loopback alias.
# This does not allocate an overlapping Docker network on an HA host.
smoke_python() {
  {
    cat <<'PYCLIENT'
import http.client
import urllib.request

class SupervisorConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, source_address=("172.30.32.2", 0), **kwargs)

class SupervisorHandler(urllib.request.HTTPHandler):
    def http_open(self, request):
        return self.do_open(SupervisorConnection, request)

urllib.request.install_opener(urllib.request.build_opener(SupervisorHandler))
PYCLIENT
    cat
  } | docker exec -i "$name" python -
}
# Exercise the real S6 -> bashio -> run.sh startup chain before the isolated
# application checks below. Seed the Bashio Supervisor-options cache so this
# needs no live Supervisor. AppArmor enforcement still needs a Linux HA host.
docker run -d --name "$name" --network none --cap-add NET_ADMIN \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint /bin/sh "$image" -c '
    mkdir -p /tmp/.bashio
    printf "%s\n" '\''{"supervisor":"2026.10.5"}'\'' > /tmp/.bashio/info.cache
    printf "%s\n" '\''{"ingress_require_login":true}'\'' > /tmp/.bashio/addons.self.options.config.cache
    printf "%s\n" '\''{"ingress_require_login":true}'\'' > /tmp/.bashio/addons.self.options.cache
    exec /init /run.sh
  ' >/dev/null
docker exec "$name" ip addr add 172.30.32.2/32 dev lo
smoke_python <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:8099"
for _ in range(30):
    try:
        request = urllib.request.Request(
            base + "/", headers={"X-Ingress-Path": "/api/hassio/ingress/synthetic"}
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            assert "first-run setup" in response.read().decode()
        break
    except (OSError, urllib.error.URLError):
        time.sleep(1)
else:
    raise SystemExit("Add-on S6 startup failed")
print("Add-on S6 startup check passed")
PY
if docker logs "$name" 2>&1 | grep -q 'Control server error'; then
  echo "Unexpected Gunicorn control server error" >&2
  exit 1
fi
docker exec "$name" test ! -e /root/.gunicorn/gunicorn.ctl
docker rm -f "$name" >/dev/null
# The image CMD needs bashio and the Supervisor; launch gunicorn directly the
# same way run.sh does, with no configuration so the wizard takes over.
docker run -d --name "$name" --network none --read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint gunicorn -e NETADMIN_ADDON=1 -e NETADMIN_SUPERVISOR_VERSION=2026.10.5 \
  "$image" \
  --bind 0.0.0.0:8099 --workers 1 netadmin.wsgi:app >/dev/null
docker exec "$name" ip addr add 172.30.32.2/32 dev lo
smoke_python <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:8099"
ingress = {"X-Ingress-Path": "/api/hassio/ingress/synthetic"}
for _ in range(30):
    try:
        request = urllib.request.Request(base + "/", headers=ingress)
        with urllib.request.urlopen(request, timeout=2) as response:
            page = response.read().decode()
        break
    except (OSError, urllib.error.URLError):
        time.sleep(1)
else:
    raise SystemExit("Add-on image failed to start")
assert "first-run setup" in page, "Setup wizard did not render through ingress"
assert 'href="/api/hassio/ingress/synthetic/static/app.css"' in page
assert "over HTTPS to sign in" not in page

# Without the ingress header the wizard must not exist.
try:
    urllib.request.urlopen(base + "/", timeout=2)
except urllib.error.HTTPError as error:
    assert error.code == 404, f"Non-ingress / returned {error.code}"
else:
    raise AssertionError("Setup wizard is reachable outside ingress")
for path in ("/services", "/apply"):
    request = urllib.request.Request(base + path, method="POST", data=b"")
    try:
        urllib.request.urlopen(request, timeout=2)
    except urllib.error.HTTPError as error:
        assert error.code == 404, f"Non-ingress {path} returned {error.code}"
    else:
        raise AssertionError(f"{path} is reachable outside ingress")
print("Add-on ingress isolation checks passed")
PY
# An existing environment file must lock the wizard.
docker run --rm --mount "type=volume,source=$volume,target=/config" \
  --entrypoint sh "$image" -c \
  "printf \"NETADMIN_SECRET_KEY='smoke'\n\" > /config/netadmin.env"
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network none --read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint gunicorn -e NETADMIN_ADDON=1 -e NETADMIN_SUPERVISOR_VERSION=2026.10.5 \
  "$image" \
  --bind 0.0.0.0:8099 --workers 1 netadmin.wsgi:app >/dev/null
docker exec "$name" ip addr add 172.30.32.2/32 dev lo
smoke_python <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:8099"
ingress = {"X-Ingress-Path": "/api/hassio/ingress/synthetic"}
for _ in range(30):
    try:
        request = urllib.request.Request(base + "/", headers=ingress)
        with urllib.request.urlopen(request, timeout=2) as response:
            page = response.read().decode()
        break
    except (OSError, urllib.error.URLError):
        time.sleep(1)
else:
    raise SystemExit("Configured add-on image failed to start")
assert "Setup complete" in page, "Configured wizard did not lock itself"
assert "Emergency root account" not in page, "Configured wizard still collects secrets"
print("Add-on wizard locking checks passed")
PY
# Check the configured application's ingress boundary using the packaged code.
# Synthetic settings avoid depending on any external network services.
docker exec -i "$name" python - <<'PY'
from pathlib import Path
import re
from dataclasses import replace
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from netadmin.app import create_app
from netadmin.config import Settings

prefix = "/api/hassio_ingress/synthetic"
headers = {"X-Ingress-Path": prefix, "X-Forwarded-Proto": "https"}
with TemporaryDirectory() as directory:
    app = create_app(Settings(
        secret_key="smoke", root_password_hash="unused", data_dir=Path(directory)
    ))
    app.config["APPLICATION_ROOT"] = prefix
    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = "172.30.32.2"
    response = client.get("/", headers=headers)
    assert urlsplit(response.location).path == prefix + "/login"
    response = client.get("/login", headers=headers)
    assert response.status_code == 200
    assert 'href="' + prefix + '/static/app.css"' in response.text
    assert "over HTTPS to sign in" not in response.text
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie and "Path=" + prefix in cookie
    assert client.get("/static/app.css", headers=headers).status_code == 200
    token = app.extensions["netadmin_store"].create_session("smoke-admin", "admin", 60)
    client.set_cookie("netadmin_session", token, path=prefix)
    response = client.get("/settings", headers=headers)
    assert response.status_code == 200 and "Connection settings" in response.text
    csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    response = client.post("/settings/test/dns", data={"csrf_token": csrf},
                           headers={**headers, "Referer": "https://localhost" + prefix + "/settings"})
    assert response.status_code == 200 and "Not configured" in response.text
    # All checkboxes omitted: disable services and apply without restarting.
    action_headers = {**headers, "Referer": "https://localhost" + prefix + "/settings"}
    response = client.post("/settings", data={"csrf_token": csrf}, headers=action_headers)
    assert response.status_code == 302
    assert app.extensions["netadmin_settings"].dns_enabled is False
    response = client.post("/settings/reload", data={"csrf_token": csrf}, headers=action_headers)
    assert response.status_code == 302
    assert client.get("/settings", headers=headers).status_code == 200
    # Delegation accepts only a real Supervisor peer and an administrator identity.
    app.extensions["netadmin_settings"] = replace(
        app.extensions["netadmin_settings"], ingress_require_login=False
    )
    delegated = app.test_client()
    delegated.environ_base["REMOTE_ADDR"] = "172.30.32.2"
    identity = {**headers, "X-Remote-User-Id": "smoke-ha-admin",
                "X-Remote-User-Groups": "system-admin"}
    response = delegated.get("/", headers=identity)
    assert response.status_code == 200 and "Home Assistant session" in response.text
    assert "netadmin_session=" not in str(response.headers.getlist("Set-Cookie"))
    assert delegated.get("/", headers=headers).status_code == 302
    assert delegated.get("/").status_code == 302
    assert delegated.get("/", headers=identity,
                         environ_overrides={"REMOTE_ADDR": "127.0.0.1"}).status_code == 403
    # HTTP ingress needs a usable CSRF cookie, while HTTPS and direct cookies
    # remain Secure. The test action reads configuration without changing it.
    http_ingress = app.test_client()
    http_ingress.environ_base["REMOTE_ADDR"] = "172.30.32.2"
    http_headers = {**identity, "X-Forwarded-Proto": "http"}
    http_base = "http://localhost" + prefix
    response = http_ingress.get("/settings", base_url=http_base, headers=http_headers)
    cookie = response.headers["Set-Cookie"]
    assert "; Secure;" not in cookie and "Path=" + prefix in cookie
    csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)
    assert http_ingress.post("/settings/test/dns", base_url=http_base,
                             headers=http_headers).status_code == 400
    response = http_ingress.post("/settings/test/dns", base_url=http_base,
                                 headers=http_headers, data={"csrf_token": csrf})
    assert response.status_code == 200 and "Disabled" in response.text
    response = app.test_client().get("/login", base_url="http://localhost")
    assert "; Secure;" in response.headers["Set-Cookie"]
print("Configured add-on ingress checks passed")
print("HTTP ingress CSRF and direct Secure cookie checks passed")
print("Packaged settings and CSRF-protected diagnostics checks passed")
print("Connection save/reload without restart check passed")
print("Delegated ingress authentication and direct-access isolation checks passed")
PY
