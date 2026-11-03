#!/usr/bin/env bash
# Exercise the real mTLS registration agent -> private Unix controller gateway.
set -euo pipefail
image="${1:?Usage: smoke_ca_stack.sh <ca-runtime-image>}"
name="netadmin-ca-stack-${RANDOM}"
cleanup() {
  result=$?
  if ((result)); then docker logs --tail 12 "$name-runtime" >&2 || true; docker logs --tail 12 "$name-agent" >&2 || true; fi
  docker rm -f "$name-runtime" "$name-agent" >/dev/null 2>&1 || true
  docker volume rm "$name-fixture" "$name-state" "$name-control" "$name-ledger" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
  docker image rm "$name-agent-image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker build -q -f docker/Dockerfile.ca-agent -t "$name-agent-image" . >/dev/null
docker network create "$name" >/dev/null
docker run --rm -i -v "$name-fixture:/fixture" --entrypoint python "$image" - <<'PY'
import os
os.umask(0o077)
from pathlib import Path
from datetime import UTC,datetime,timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
p=Path('/fixture');(p/'agent').mkdir();(p/'client').mkdir();(p/'secrets').mkdir()
now=datetime.now(UTC)
key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic transport CA')])
ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False).sign(key,hashes.SHA256())
for role,basename,eku in [('agent','server',ExtendedKeyUsageOID.SERVER_AUTH),('client','client',ExtendedKeyUsageOID.CLIENT_AUTH)]:
 leaf_key=ec.generate_private_key(ec.SECP256R1())
 cert=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,role)])).issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True).add_extension(x509.ExtendedKeyUsage([eku]),False).add_extension(x509.SubjectAlternativeName([x509.DNSName('ca-agent')]),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256())
 (p/role/(basename+'.crt')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (p/role/(basename+'.key')).write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 (p/role/'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
(p/'secrets/management-token').write_text('synthetic-management-token-longer-than-32-characters')
PY
docker run -d --name "$name-runtime" --network "$name" --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL --read-only --tmpfs /tmp \
  -v "$name-state:/state" -v "$name-control:/control" -v "$name-fixture:/fixture:ro" \
  -e CA_MANAGEMENT_TOKEN_FILE=/fixture/secrets/management-token "$image" >/dev/null
docker run -d --name "$name-agent" --network "$name" --network-alias ca-agent --cap-drop ALL --read-only --tmpfs /tmp \
  -v "$name-control:/control:ro" -v "$name-ledger:/data" \
  --mount "type=volume,source=$name-fixture,target=/pki,volume-subpath=agent,readonly" \
  --mount "type=volume,source=$name-fixture,target=/secrets,volume-subpath=secrets,readonly" \
  -e NETADMIN_AGENT_TOKEN=synthetic-leaf-token -e CA_CONTROL_SOCKET=/control/ca.sock \
  -e CA_MANAGEMENT_TOKEN_FILE=/secrets/management-token "$name-agent-image" >/dev/null
docker exec -i "$name-runtime" python - <<'PY'
import ssl,time,uuid
from pathlib import Path
import httpx
ctx=ssl.create_default_context(cafile='/fixture/client/ca.crt');ctx.load_cert_chain('/fixture/client/client.crt','/fixture/client/client.key')
headers={'Authorization':'Bearer synthetic-leaf-token','X-CA-Management-Token':Path('/fixture/secrets/management-token').read_text()}
client=httpx.Client(verify=ctx,base_url='https://ca-agent:8084',headers=headers,timeout=30)
for attempt in range(30):
 try:
  response=client.get('/authorities');response.raise_for_status();break
 except httpx.HTTPError:
  if attempt==29:raise
  time.sleep(1)
assert response.json()['state']=='key_ready'
assert client.get('/authorities',headers={'X-CA-Management-Token':'incorrect'}).status_code==403
assert client.get('/authorities',headers={'Authorization':'Bearer incorrect'}).status_code==401
body={'request_id':uuid.uuid4().hex,'common_name':'Gateway Root','days':7300,'path_length':1}
result=client.post('/authorities/root',json=body);assert result.status_code==200,result.text
assert client.get('/authorities').json()['authorities'][0]['common_name']=='Gateway Root'
assert not client.get('/authorities').json().get('private_key')
try:
 with httpx.Client(verify=ssl.create_default_context(cafile='/fixture/client/ca.crt')) as bad:
  bad.get('https://ca-agent:8084/authorities')
except httpx.HTTPError:pass
else:raise AssertionError('Missing TLS client certificate accepted')
print('Real mTLS/bearer + separate management scope, Unix gateway and UI root-creation payload passed')
PY
