#!/usr/bin/env bash
# Disposable full runtime: boot key, real multi-issuer signing, archive and restart.
set -euo pipefail
image="${1:?Usage: smoke_ca_runtime.sh <ca-runtime-image>}"
name="netadmin-ca-runtime-smoke-${RANDOM}"
cleanup() {
  code=$?
  if ((code)); then docker logs --tail 20 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$name-state" "$name-control" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m -v "$name-state:/state" -v "$name-control:/control" \
  -e CA_MANAGEMENT_TOKEN_FILE=/state/token --entrypoint sh "$image" -c \
  'printf %s synthetic-management-token-with-more-than-32-characters > /state/token; exec python -m netadmin.ca_runtime.app' >/dev/null
docker exec -i "$name" python - <<'PY'
import json,time,uuid
from pathlib import Path
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
transport=httpx.HTTPTransport(uds='/control/ca.sock')
client=httpx.Client(transport=transport,base_url='http://controller',headers={'X-CA-Management-Token':Path('/state/token').read_text()},timeout=90)
for attempt in range(30):
    try:
        status=client.get('/authorities');status.raise_for_status();break
    except httpx.HTTPError:
        if attempt==29:raise
        time.sleep(1)
before=status.json()['public_key_sha256']
Path('/state/test-key-fingerprint').write_text(before)
def post(path,**body):
    body.setdefault('request_id',uuid.uuid4().hex)
    response=client.post(path,json=body)
    assert response.status_code==200,(path,response.status_code,response.text)
    return response.json()
root=post('/authorities/root',common_name='Synthetic Root',days=7300,path_length=2)['id']
issuer_ids=[]
for label in ('Servers','Devices'):
    issuer=post('/authorities/subordinate',parent_id=root,common_name=label,days=365,path_length=0,
                service_host='localhost',dns_suffixes='example.test' if label=='Servers' else '',ip_ranges='192.168.0.0/16' if label=='Devices' else '',leaf_days=30)['id']
    issuer_ids.append(issuer)
from netadmin.ca_runtime.issuer import run
for issuer in issuer_ids:
    directory=Path('/state/authorities')/issuer
    metadata=json.loads((directory/'metadata.json').read_text())
    port=metadata['port']
    for attempt in range(30):
        try:
            assert run(['ca','health','--ca-url',f'https://localhost:{port}','--root',str(directory/'root.crt')])=='ok';break
        except Exception:
            if attempt==29:
                print((directory/'service.log').read_text());raise
            time.sleep(1)
    key=ec.generate_private_key(ec.SECP256R1())
    from ipaddress import ip_address
    identity='192.168.50.10' if metadata['policy']['ips'] else 'service.example.test'
    san=x509.IPAddress(ip_address(identity)) if metadata['policy']['ips'] else x509.DNSName(identity)
    csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,identity)])).add_extension(x509.SubjectAlternativeName([san]),False).sign(key,hashes.SHA256())
    body={'csr':csr.public_bytes(serialization.Encoding.PEM).decode(),'days':1,'request_id':uuid.uuid4().hex}
    signed=post(f'/authorities/{issuer}/issue',**body)
    replay=post(f'/authorities/{issuer}/issue',**body)
    assert signed==replay
    cert=x509.load_pem_x509_certificate(signed['pem'].encode())
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert cert.issuer==x509.load_pem_x509_certificate((directory/'ca.crt').read_bytes()).subject
    assert cert.public_key().public_numbers()==key.public_key().public_numbers()
    bad_csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'outside.invalid')])).add_extension(x509.SubjectAlternativeName([x509.DNSName('outside.invalid')]),False).sign(key,hashes.SHA256())
    denied=client.post(f'/authorities/{issuer}/issue',json={'request_id':uuid.uuid4().hex,'csr':bad_csr.public_bytes(serialization.Encoding.PEM).decode(),'days':1})
    assert denied.status_code==409
    # Native renewal and CRL generation must work for each independently configured issuer.
    password=directory/'test-leaf-password';password.write_text('synthetic-leaf-password')
    leaf_key=directory/'test-leaf.key';leaf_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.read_bytes())))
    leaf=directory/'test-leaf.pem';leaf.write_text(signed['pem'])
    flags=['--ca-url',f'https://localhost:{port}','--root',str(directory/'root.crt')]
    run(['ca','renew',str(leaf),str(leaf_key),'--out',str(directory/'renewed.pem'),'--force','--mtls=false','--password-file',str(password),*flags])
    assert x509.load_pem_x509_certificate((directory/'renewed.pem').read_bytes()).serial_number!=cert.serial_number
    result=post(f'/authorities/{issuer}/revoke',serial=format(cert.serial_number,'x'),reason='5')
    assert result['revoked']
    assert client.get(f'/authorities/{issuer}/certificates').json()['certificates']
    import ssl
    with httpx.Client(verify=ssl.create_default_context(cafile=str(directory/'root.crt'))) as public:
        crl=x509.load_der_x509_crl(public.get(f'https://localhost:{port}/1.0/crl').content)
        assert crl.get_revoked_certificate_by_serial_number(cert.serial_number)
backup=post('/authorities/export-root',password='synthetic-independent-recovery-passphrase')
post('/authorities/archive-root',recovery_key=backup['key'],recovery_password='synthetic-independent-recovery-passphrase',confirmation='ARCHIVE ROOT')
assert not Path('/state/root.key').exists()
assert client.get('/authorities',headers={'X-CA-Management-Token':'incorrect'}).status_code==403
print('Root boot key, two native issuers, leaf signing/replay, renewal, revocation, CRLs and root archival passed')
PY
docker restart "$name" >/dev/null
docker exec -i "$name" python - <<'PY'
import time
from pathlib import Path
import httpx
client=httpx.Client(transport=httpx.HTTPTransport(uds='/control/ca.sock'),base_url='http://controller',headers={'X-CA-Management-Token':Path('/state/token').read_text()})
for attempt in range(30):
    try:
        response=client.get('/authorities');response.raise_for_status();state=response.json();break
    except httpx.HTTPError:
        if attempt==29:raise
        time.sleep(1)
assert state['public_key_sha256']==Path('/state/test-key-fingerprint').read_text()
assert state['root_online'] is False
assert len(state['authorities'])==3
assert not Path('/state/root.key').exists()
print('Container restart preserved public root identity, archived root and both issuers')
PY
