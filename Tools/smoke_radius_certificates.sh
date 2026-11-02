#!/usr/bin/env bash
# Exercise signed lifecycle changes against a disposable native RADIUS daemon.
set -euo pipefail
agent_image="${1:?Usage: smoke_radius_certificates.sh <radius-agent-image>}"
name="netadmin-cert-smoke-${RANDOM}"
volume="${name}-certs"
service_image="${name}-service"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 35 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker image rm "$service_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker build -q -f docker/Dockerfile.freeradius -t "$service_image" . >/dev/null
docker run -d --name "$name" --network none \
  --mount "type=volume,source=$volume,target=/etc/raddb/certs" \
  "$service_image" -X >/dev/null
ready=false
# Packaged bootstrap generates DH parameters; hosted ARM runners can need minutes.
for _ in $(seq 300); do
  if docker logs "$name" 2>&1 | grep 'Ready to process requests' >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'RADIUS did not start' >&2; exit 1; }
docker run --rm -i --network none --pid "container:$name" \
  --mount "type=volume,source=$volume,target=/etc/raddb/certs" \
  -e NETADMIN_AGENT_TOKEN=synthetic-cert-smoke -e RADIUS_CERT_MANAGEMENT=true \
  --entrypoint python "$agent_image" - <<'PY'
from pathlib import Path
from cryptography import x509
from netadmin.agents.radius import create_radius_agent

client = create_radius_agent().test_client()
auth = {'Authorization': 'Bearer synthetic-cert-smoke'}
status = client.get('/certificates', headers=auth).json
assert status['available'] and status['can_manage'], status
for action in ('create-server', 'renew-server', 'revoke-server', 'refresh-crl', 'renew-ca', 'retire-ca'):
    before = status
    body = {'action': action, 'expected_ca': before['ca']['fingerprint'],
            'expected_server': before['server']['fingerprint'], 'confirmation': 'REPLACE CA'}
    if action in {'create-server', 'renew-server'}:
        body.update(common_name='radius.smoke.test', sans='radius.smoke.test,192.0.2.15', days=365)
    response = client.post('/certificates', json=body, headers=auth)
    assert response.status_code == 200, (action, response.json)
    status = client.get('/certificates', headers=auth).json
    assert status['available'] and status['can_manage'], status
    if action == 'revoke-server':
        crl = x509.load_pem_x509_crl(Path('/etc/raddb/certs/netadmin-crl.pem').read_bytes())
        assert crl.get_revoked_certificate_by_serial_number(int(before['server']['serial'], 16))
    if action in {'create-server', 'renew-server', 'revoke-server', 'retire-ca'}:
        assert status['server']['serial'] != before['server']['serial']
    if action in {'create-server', 'renew-server'}:
        assert status['server']['common_name'] == 'radius.smoke.test'
        assert status['server']['sans'] == 'radius.smoke.test, 192.0.2.15'
    if action in {'renew-ca', 'retire-ca'}:
        assert status['ca']['serial'] != before['ca']['serial']
    if action == 'refresh-crl':
        assert status['server']['serial'] == before['server']['serial']
        assert status['revoked_count'] == before['revoked_count']
    for kind in ('server', 'ca', 'crl'):
        download = client.get(f'/certificates/{kind}', headers=auth)
        assert download.status_code == 200 and 'PRIVATE KEY' not in download.text
    print(f'{action}: signed files installed and new native daemon acknowledged')
PY
docker exec "$name" radiusd -XC >/dev/null
echo 'RADIUS certificate lifecycle smoke passed'
