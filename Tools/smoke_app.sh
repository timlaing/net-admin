#!/usr/bin/env bash
# Smoke-test the main NetAdmin application image.
#
# Verifies the container boots, the login page renders, unauthenticated
# requests redirect to /login, CSRF protection rejects tokenless POSTs, a
# correct root login returns a Secure session cookie, and that cookie then
# reaches the dashboard. Uses only synthetic credentials.
set -euo pipefail
image="${1:-netadmin:test}"
name="netadmin-smoke-${RANDOM}"
volume="${name}-data"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 100 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$volume" >/dev/null
# The compose stack mounts a named volume at /data; mirror that and generate a
# synthetic Argon2id root hash inside the image itself.
root_hash="$(docker run --rm --entrypoint python "$image" -c \
  'from argon2 import PasswordHasher; print(PasswordHasher().hash("smoke-test-password"))')"
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=volume,source=$volume,target=/data" \
  -e NETADMIN_SECRET_KEY=smoke-test-secret-key \
  -e NETADMIN_ROOT_PASSWORD_HASH="$root_hash" \
  -p 127.0.0.1::8099 "$image" >/dev/null
port="$(docker port "$name" 8099/tcp | sed 's/.*://')"
NETADMIN_SMOKE_PORT="$port" python3 - <<'PY'
import os
import re
import time
import urllib.error
import urllib.request

base = "http://127.0.0.1:" + os.environ["NETADMIN_SMOKE_PORT"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects as HTTPError so assertions can inspect them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


opener = urllib.request.build_opener(NoRedirect)


def call(url, data=None, headers=None):  # noqa: ANN001, ANN202
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(request, timeout=2) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


for _ in range(30):
    try:
        status, headers, page = call(base + "/login")
        if status == 200:
            break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(1)
else:
    raise SystemExit("Application image failed to start")
assert "Network administration" in page, "Login page did not render"
match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
assert match, "Login form is missing its CSRF token"
csrf = match.group(1)
# The CSRF token is bound to Flask's own session cookie, not the auth cookie.
flask_session = headers.get("Set-Cookie", "").split("session=", 1)
assert len(flask_session) == 2, "Login page did not set a CSRF session cookie"
flask_session = flask_session[1].split(";", 1)[0]
csrf_cookie = {"Cookie": "session=" + flask_session}

# Unauthenticated pages redirect to the login screen.
status, headers, _ = call(base + "/")
assert status in (302, 401), f"/ returned {status} without authentication"
assert "/login" in headers.get("Location", ""), "/ did not redirect to /login"

# Home Assistant headers must not bypass standalone login.
status, headers, _ = call(base + "/", headers={
    "X-Ingress-Path": "/api/hassio_ingress/forged",
    "X-Remote-User-Id": "forged-admin", "X-Remote-User-Groups": "system-admin",
})
assert status == 302 and headers.get("Location", "").startswith("/login")

# CSRF protection rejects a tokenless login attempt.
status, _, _ = call(
    base + "/login", data=b"username=root&password=wrong"
)
assert status == 400, f"CSRF-less POST returned {status}"

# A correct root login sets a Secure session cookie and redirects onward.
body = "username=root&password=smoke-test-password&csrf_token=" + csrf
status, headers, _ = call(
    base + "/login",
    data=body.encode(),
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        **csrf_cookie,
    },
)
assert status == 302, f"Root login returned {status}"
cookie = headers.get("Set-Cookie", "")
assert "netadmin_session=" in cookie, "Login did not set a session cookie"
assert "Secure" in cookie, "Session cookie is missing the Secure attribute"
authed_session = cookie.split("netadmin_session=", 1)[1].split(";", 1)[0]

# The authenticated session reaches the dashboard.
status, _, dash = call(base + "/", headers={"Cookie": "netadmin_session=" + authed_session})
assert status == 200, f"Authenticated / returned {status}"
assert "Network overview" in dash, "Dashboard did not render"
print("Application container smoke checks passed")
PY
