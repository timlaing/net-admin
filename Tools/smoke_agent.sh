#!/usr/bin/env bash
# Smoke-test a NetAdmin service agent image (DHCP, DNS or RADIUS) over mTLS.
#
# Generates a throwaway CA, server certificate and client certificate, starts
# the agent with the PKI mounted at /pki (the path the container CMD expects),
# then verifies /health over client-cert TLS, bearer-token enforcement, and
# that unauthenticated clients are rejected at the TLS layer.
set -euo pipefail
image="${1:?Usage: smoke_agent.sh <image> [port]}"
probe=health
probe_field=status
case "$image" in
  *radius*) default_port=8082 ;;
  *dns*) default_port=8083; probe=capabilities; probe_field=read_only ;;
  *) default_port=8081 ;;
esac
port="${2:-$default_port}"
name="netadmin-agent-smoke-${RANDOM}"
pki="$(mktemp -d)"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 100 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$pki"
}
trap cleanup EXIT
# Throwaway PKI: the agent requires client certificates signed by this CA.
# Every certificate carries explicit X.509v3 extensions: the newer TLS stacks
# in the updated base images (OpenSSL 3.5 via Ubuntu 25.10 / Python 3.14's
# stricter verification) reject a CA without basicConstraints and keyUsage.
openssl genrsa -out "$pki/ca.key" 2048 2>/dev/null
openssl req -new -key "$pki/ca.key" -subj "/CN=NetAdmin smoke CA" -out "$pki/ca.csr" 2>/dev/null
openssl x509 -req -in "$pki/ca.csr" -signkey "$pki/ca.key" -sha256 -days 2 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n') \
  -out "$pki/ca.crt" 2>/dev/null
openssl genrsa -out "$pki/server.key" 2048 2>/dev/null
openssl req -new -key "$pki/server.key" -subj "/CN=localhost" -out "$pki/server.csr" 2>/dev/null
openssl x509 -req -in "$pki/server.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" \
  -CAcreateserial -days 2 -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nauthorityKeyIdentifier=keyid\n') \
  -out "$pki/server.crt" 2>/dev/null
openssl genrsa -out "$pki/client.key" 2048 2>/dev/null
openssl req -new -key "$pki/client.key" -subj "/CN=netadmin-smoke" -out "$pki/client.csr" 2>/dev/null
openssl x509 -req -in "$pki/client.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" \
  -CAcreateserial -days 2 -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid\n') \
  -out "$pki/client.crt" 2>/dev/null
# Synthetic service logs are mounted read-only beside the throwaway PKI.
mkdir -p "$pki/logs/radacct/192.0.2.1"
cat > "$pki/logs/radius.log" <<'LOG'
Mon Nov  2 10:00:00 2026 : Auth: Login OK: [synthetic-user/DO-NOT-RETURN] (from client synthetic-ap port 0)
LOG
cat > "$pki/logs/dhcp.log" <<'LOG'
Nov  2 10:00:00 host dhcpd: DHCPACK on 192.0.2.10 to aa:bb:cc:dd:ee:ff (synthetic-phone) via eth0
LOG
cat > "$pki/logs/dns.log" <<'LOG'
02-Nov-2026 10:00:00.123 updating zone 'example/IN': adding an RR at 'synthetic.example' A 192.0.2.10
LOG
cat > "$pki/logs/radacct/192.0.2.1/detail-smoke" <<'LOG'
Mon Nov  2 10:00:00 2026
    User-Name = "synthetic-user"
    NAS-IP-Address = 192.0.2.1
    Acct-Session-Id = "synthetic-session"
    Acct-Status-Type = Stop
    Timestamp = 1000

LOG
# The agent runs with --cap-drop ALL: its root user cannot traverse the
# runner-owned 0700 temp dir or read 0600 files without CAP_DAC_OVERRIDE
# (Docker Desktop's file sharing hides this on macOS), so open the
# throwaway PKI up. These are ephemeral two-day smoke certificates.
chmod -R a+rX "$pki"
docker run -d --name "$name" --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$pki,target=/pki,readonly" \
  -e NETADMIN_AGENT_TOKEN=smoke-test-agent-token \
  -e NETADMIN_AGENT_READ_ONLY=true \
  -e RADIUS_AUTH_LOG_FILE=/pki/logs/radius.log \
  -e RADIUS_ACCOUNTING_DIR=/pki/logs/radacct \
  -e DHCP_LOG_FILE=/pki/logs/dhcp.log \
  -e DNS_UPDATE_LOG_FILE=/pki/logs/dns.log \
  -p "127.0.0.1::$port" "$image" >/dev/null
mapped="$(docker port "$name" "$port"/tcp | sed 's/.*://')"
url="https://127.0.0.1:$mapped/$probe"
started=false
for _ in $(seq 30); do
  if curl -fsS --cacert "$pki/ca.crt" --cert "$pki/client.crt" --key "$pki/client.key" \
      -H 'Authorization: Bearer smoke-test-agent-token' "$url" 2>/dev/null \
      | grep -q "\"$probe_field\""; then
    started=true
    break
  fi
  sleep 1
done
if [[ "$started" != true ]]; then
  echo "Agent image failed to start" >&2
  exit 1
fi
# A valid client certificate without the bearer token is refused.
status="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$pki/ca.crt" \
  --cert "$pki/client.crt" --key "$pki/client.key" "$url")"
[[ "$status" == "401" ]] || { echo "Expected 401 without token, got $status" >&2; exit 1; }
# A correct bearer token is accepted.
body="$(curl -fsS --cacert "$pki/ca.crt" --cert "$pki/client.crt" --key "$pki/client.key" \
  -H 'Authorization: Bearer smoke-test-agent-token' "$url")"
echo "$body" | grep -q "\"$probe_field\"" || { echo "Unexpected /health body: $body" >&2; exit 1; }
# Clients without a certificate cannot complete the TLS handshake.
if curl -fsS --cacert "$pki/ca.crt" "$url" >/dev/null 2>&1; then
  echo "Agent accepted a TLS connection without a client certificate" >&2
  exit 1
fi
echo "Agent container mTLS and token smoke checks passed"
docker exec -i "$name" python3 - "$port" "$probe" <<'PY'
import sys
import httpx
from pathlib import Path
from netadmin.services.agents import AgentClient

client = AgentClient(
    'https://127.0.0.1:' + sys.argv[1], 'smoke-test-agent-token',
    Path('/pki/ca.crt'), Path('/pki/client.crt'), Path('/pki/client.key'),
)
probe = client.get(sys.argv[2])
assert probe.get('status') == 'ok' or probe.get('read_only') is True
print('Application HTTPX client passed real mTLS with an explicit CA file')
resources = {'8081': {'leases': ('hostname', 'synthetic-phone')},
             '8082': {'logins': ('user', 'synthetic-user'), 'sessions': ('user', 'synthetic-user')},
             '8083': {'ddns': ('name', 'synthetic.example')}}
for resource, (field, value) in resources[sys.argv[1]].items():
    endpoint = 'logs/' + resource
    payload = client.get(endpoint)
    assert payload['status'] == 'available', payload
    assert payload['rows'][0][field] == value, payload
    assert 'DO-NOT-RETURN' not in str(payload)
    try:
        client.post(endpoint, {})
    except httpx.HTTPStatusError as error:
        assert error.response.status_code == 403
    else:
        raise AssertionError('Log endpoint accepted a write')
    client.headers['Authorization'] = 'Bearer invalid-synthetic-token'
    try:
        client.get(endpoint)
    except httpx.HTTPStatusError as error:
        assert error.response.status_code == 401
    else:
        raise AssertionError('Log endpoint accepted an invalid token')
    finally:
        client.headers['Authorization'] = 'Bearer smoke-test-agent-token'
print('Read-only service logs passed real mTLS, token checks and credential redaction')
PY
