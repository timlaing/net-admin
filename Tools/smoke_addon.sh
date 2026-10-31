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
docker volume create "$volume" >/dev/null
# Exercise the real S6 -> bashio -> run.sh startup chain before the isolated
# application checks below. Seed the Bashio Supervisor-options cache so this
# needs no live Supervisor. AppArmor enforcement still needs a Linux HA host.
docker run -d --name "$name" \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint /bin/sh -p 127.0.0.1::8099 "$image" -c '
    mkdir -p /tmp/.bashio
    printf "%s\n" '\''{"dhcp_backend":"isc","dns_server":"dns.internal","dns_zones":"","dhcp_agent_url":"https://dhcp.internal:8081","radius_agent_url":"https://radius.internal:8082"}'\'' > /tmp/.bashio/addons.self.options.config.cache
    exec /init /run.sh
  ' >/dev/null
port="$(docker port "$name" 8099/tcp | sed 's/.*://')"
NETADMIN_SMOKE_PORT="$port" python3 - <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:" + os.environ["NETADMIN_SMOKE_PORT"]
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
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint gunicorn -e NETADMIN_ADDON=1 \
  -p 127.0.0.1::8099 "$image" \
  --bind 0.0.0.0:8099 --workers 1 netadmin.wsgi:app >/dev/null
port="$(docker port "$name" 8099/tcp | sed 's/.*://')"
NETADMIN_SMOKE_PORT="$port" python3 - <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:" + os.environ["NETADMIN_SMOKE_PORT"]
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
assert "Open Home Assistant over HTTPS" in page

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
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$volume,target=/config" \
  --entrypoint gunicorn -e NETADMIN_ADDON=1 \
  -p 127.0.0.1::8099 "$image" \
  --bind 0.0.0.0:8099 --workers 1 netadmin.wsgi:app >/dev/null
port="$(docker port "$name" 8099/tcp | sed 's/.*://')"
NETADMIN_SMOKE_PORT="$port" python3 - <<'PY'
import os
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:" + os.environ["NETADMIN_SMOKE_PORT"]
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
    response = client.get("/", headers=headers)
    assert urlsplit(response.location).path == prefix + "/login"
    response = client.get("/login", headers=headers)
    assert response.status_code == 200
    assert 'href="' + prefix + '/static/app.css"' in response.text
    assert "Open Home Assistant over HTTPS" not in response.text
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
print("Configured add-on ingress checks passed")
print("Packaged settings and CSRF-protected diagnostics checks passed")
print("Connection save/reload without restart check passed")
PY
