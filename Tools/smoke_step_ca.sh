#!/usr/bin/env bash
# Disposable real step-ca issuance/renewal/revocation and native RADIUS activation.
set -euo pipefail
image="${1:?Usage: smoke_step_ca.sh <radius-agent-image|ca-agent-image>}"
name="netadmin-step-smoke-${RANDOM}"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 20 "$name-ca" >&2 || true; fi
  docker rm -f "$name-ca" "$name-radius" >/dev/null 2>&1 || true
  docker volume rm "$name-ca-data" "$name-trust" "$name-radius-data" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
  docker image rm "$name-radius-image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$name" >/dev/null
docker run --rm -i --user 0 --entrypoint sh \
  -v "$name-ca-data:/home/step" -v "$name-trust:/trust" \
  smallstep/step-ca:0.30.2 -s <<'INIT'
set -eu
printf '%s' 'synthetic-smoke-password' > /home/step/password
step ca init --deployment-type standalone --name 'Synthetic CA' --dns step-ca \
  --address :9000 --provisioner netadmin --password-file /home/step/password
cp /home/step/certs/root_ca.crt /trust/root_ca.crt
INIT
# Enable a public CRL and short test lifetimes using synthetic configuration only.
docker run --rm -i --entrypoint python -v "$name-ca-data:/ca" "$image" - <<'CONFIG'
import json
from pathlib import Path
p = Path('/ca/config/ca.json')
c = json.loads(p.read_text())
c['crl'] = {'enabled': True, 'generateOnRevoke': True}
c['authority']['provisioners'][0]['claims'] = {
 'minTLSCertDuration': '1m', 'maxTLSCertDuration': '8760h', 'defaultTLSCertDuration': '24h'}
p.write_text(json.dumps(c))
CONFIG
docker run -d --name "$name-ca" --user 0 --network "$name" --network-alias step-ca \
  -v "$name-ca-data:/home/step" smallstep/step-ca:0.30.2 \
  step-ca /home/step/config/ca.json --password-file /home/step/password >/dev/null
# The CA image has its own CLI installation; exercise its actual signing path too.
if [[ "$image" == *ca-agent* ]]; then
  docker run --rm -i --network "$name" -v "$name-trust:/trust:ro" \
    -e NETADMIN_AGENT_TOKEN=synthetic -e STEP_CA_URL=https://step-ca:9000 \
    -e STEP_CA_ROOT=/trust/root_ca.crt -e STEP_CA_PROVISIONER=netadmin \
    -e STEP_CA_PASSWORD_FILE=/tmp/provisioner-password -e CA_DATA_DIR=/tmp/ledger \
    --entrypoint python "$image" - <<'CA_ONLY'
import time
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from netadmin.agents.ca import create_ca_agent
from netadmin.services.step_ca import run_step, connection_flags, issued_matches_csr

Path('/tmp/provisioner-password').write_text('synthetic-smoke-password')
for attempt in range(30):
    try:
        run_step(['ca', 'health', *connection_flags()]); break
    except Exception:
        if attempt == 29: raise
        time.sleep(1)
key = ec.generate_private_key(ec.SECP256R1())
csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ca-smoke.test')]))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName('ca-smoke.test')]), False)
       .sign(key, hashes.SHA256()))
client = create_ca_agent().test_client()
auth = {'Authorization': 'Bearer synthetic'}
payload = {'csr': csr.public_bytes(serialization.Encoding.PEM).decode(), 'days': 1}
response = client.post('/certificates', headers=auth, json=payload)
assert response.status_code == 201, response.json
issued_matches_csr(response.json['pem'].encode(), csr)
assert client.post('/certificates', headers=auth, json=payload).json == response.json
assert len(client.get('/certificates', headers=auth).json['certificates']) == 1
revoked = client.post('/certificates/' + response.json['id'] + '/revoke', headers=auth, json={'reason': 4})
assert revoked.status_code == 200, revoked.json
assert client.get('/certificates', headers=auth).json['certificates'][0]['revoked']
print('CA-agent image CLI issuance, idempotent retry and revocation passed')
CA_ONLY
  exit 0
fi
docker build -q -f docker/Dockerfile.freeradius -t "$name-radius-image" . >/dev/null
docker run -d --name "$name-radius" --network none \
  -v "$name-radius-data:/etc/raddb/certs" "$name-radius-image" -X >/dev/null
ready=false
# Packaged bootstrap generates DH parameters; hosted ARM runners can need minutes.
for _ in $(seq 300); do
  if docker logs "$name-radius" 2>&1 | grep 'Ready to process requests' >/dev/null; then
    ready=true; break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'RADIUS did not start' >&2; exit 1; }
docker run --rm -i --network "$name" --pid "container:$name-radius" \
  -v "$name-trust:/trust:ro" -v "$name-radius-data:/etc/raddb/certs" \
  -e NETADMIN_AGENT_TOKEN=synthetic -e RADIUS_CERT_MANAGEMENT=true \
  -e RADIUS_CERT_BACKEND=step-ca -e RADIUS_CERT_AUTO_RENEW=true \
  -e STEP_CA_URL=https://step-ca:9000 -e STEP_CA_ROOT=/trust/root_ca.crt \
  -e STEP_CA_PROVISIONER=netadmin -e STEP_CA_PASSWORD_FILE=/tmp/provisioner-password \
  -e CA_DATA_DIR=/tmp/ledger --entrypoint python "$image" - <<'PY'
import time
import subprocess
from pathlib import Path
from types import SimpleNamespace
from cryptography import x509
from netadmin.agents.ca import create_ca_agent
from netadmin.agents.radius import create_radius_agent
from netadmin.agents import radius_step_ca, radius_renewal
from netadmin.services.step_ca import run_step, connection_flags
import ssl
import httpx

Path('/tmp/provisioner-password').write_text('synthetic-smoke-password')
for attempt in range(30):
    try:
        run_step(['ca', 'health', *connection_flags()]); break
    except Exception:
        if attempt == 29: raise
        time.sleep(1)
ca = create_ca_agent().test_client()
auth = {'Authorization': 'Bearer synthetic'}
def issue(path, payload, **kwargs):
    response = ca.post('/' + path, json=payload, headers=auth)
    assert response.status_code == 201, response.json
    return response.json
radius_step_ca._client = lambda: SimpleNamespace(post=issue)
app = create_radius_agent()
client = app.test_client()
status = client.get('/certificates', headers=auth).json
response = client.post('/certificates', headers=auth, json={
    'action': 'enroll-step-ca', 'confirmation': 'STEP CA',
    'common_name': 'radius.example.test', 'sans': 'radius.example.test,192.0.2.15', 'days': 1,
    'expected_ca': status['ca']['fingerprint'], 'expected_server': status['server']['fingerprint'],
})
assert response.status_code == 200, response.json
status = client.get('/certificates', headers=auth).json
assert status['enrolled'] and status['auto_renew'], status
before = status['server']['serial']
# Force the due check only: signing, renewal, validation and native activation are real.
radius_renewal.renewal_due = lambda bundle: True
with app.app_context():
    assert radius_renewal.renew_once()
status = client.get('/certificates', headers=auth).json
assert status['server']['serial'] != before
assert status['server']['common_name'] == 'radius.example.test'
assert len(x509.load_pem_x509_certificates(Path('/etc/raddb/certs/server.pem').read_bytes())) == 2
inventory = ca.get('/certificates', headers=auth).json['certificates']
assert len(inventory) == 1
response = ca.post('/certificates/' + inventory[0]['id'] + '/revoke', json={'reason': 4}, headers=auth)
assert response.status_code == 200, response.json
# The CRL is a real signed object and contains the revoked initial certificate.
context = ssl.create_default_context(cafile='/trust/root_ca.crt')
with httpx.Client(verify=context, trust_env=False) as remote:
    response = remote.get('https://step-ca:9000/1.0/crl')
    assert response.status_code == 200, response.text
    crl = x509.load_der_x509_crl(response.content)
    assert crl.get_revoked_certificate_by_serial_number(int(inventory[0]['serial'], 16))
    chain = x509.load_pem_x509_certificates(Path('/etc/raddb/certs/server.pem').read_bytes())
    assert crl.is_signature_valid(chain[1].public_key())
proxy = ca.get('/crl', headers=auth)
assert proxy.status_code == 200, proxy.json
assert x509.load_pem_x509_crl(proxy.json['pem'].encode()).get_revoked_certificate_by_serial_number(int(inventory[0]['serial'], 16))
# Revoking the active renewal must prevent subsequent renewal and retain its files.
revoked = ca.post('/revoke', headers=auth, json={'serial': status['server']['serial'], 'reason': 1})
assert revoked.status_code == 200, revoked.json
before_files = Path('/etc/raddb/certs/server.pem').read_bytes()
try:
    with app.app_context(): radius_renewal.renew_once()
except subprocess.CalledProcessError as error:
    assert 'authorization' in error.stderr.lower(), error.stderr
else:
    raise AssertionError('Revoked certificate was allowed to renew')
assert Path('/etc/raddb/certs/server.pem').read_bytes() == before_files
print('step-ca CSR issuance, chain installation, token renewal, native restart and revocation passed')
PY

docker logs "$name-ca" 2>&1 | grep 'certificate has been revoked' >/dev/null
