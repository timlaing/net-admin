#!/usr/bin/env bash
# Smoke-test a NetAdmin service agent image (DHCP or RADIUS) over mTLS.
#
# Generates a throwaway CA, server certificate and client certificate, starts
# the agent with the PKI mounted at /pki (the path the container CMD expects),
# then verifies /health over client-cert TLS, bearer-token enforcement, and
# that unauthenticated clients are rejected at the TLS layer.
set -euo pipefail
image="${1:?Usage: smoke_agent.sh <image> [port]}"
case "$image" in
  *ca-agent*) default_port=8084 ;;
  *radius*) default_port=8082 ;;
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
# The agent runs with --cap-drop ALL: its root user cannot traverse the
# runner-owned 0700 temp dir or read 0600 files without CAP_DAC_OVERRIDE
# (Docker Desktop's file sharing hides this on macOS), so open the
# throwaway PKI up. These are ephemeral two-day smoke certificates.
chmod -R a+rX "$pki"
docker run -d --name "$name" --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$pki,target=/pki,readonly" \
  -e NETADMIN_AGENT_TOKEN=smoke-test-agent-token \
  -p "127.0.0.1::$port" "$image" >/dev/null
mapped="$(docker port "$name" "$port"/tcp | sed 's/.*://')"
url="https://127.0.0.1:$mapped/health"
started=false
for _ in $(seq 30); do
  if curl -fsS --cacert "$pki/ca.crt" --cert "$pki/client.crt" --key "$pki/client.key" \
      -H 'Authorization: Bearer smoke-test-agent-token' "$url" 2>/dev/null \
      | grep -q '"status"'; then
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
echo "$body" | grep -q '"status"' || { echo "Unexpected /health body: $body" >&2; exit 1; }
# Clients without a certificate cannot complete the TLS handshake.
if curl -fsS --cacert "$pki/ca.crt" "$url" >/dev/null 2>&1; then
  echo "Agent accepted a TLS connection without a client certificate" >&2
  exit 1
fi
echo "Agent container mTLS and token smoke checks passed"
docker exec -i "$name" python3 - "$port" <<'PY'
import sys
from pathlib import Path
from netadmin.services.agents import AgentClient

client = AgentClient(
    'https://127.0.0.1:' + sys.argv[1], 'smoke-test-agent-token',
    Path('/pki/ca.crt'), Path('/pki/client.crt'), Path('/pki/client.key'),
)
assert client.get('health')['status'] == 'ok'
print('Application HTTPX client passed real mTLS with an explicit CA file')
PY
