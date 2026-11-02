#!/usr/bin/env bash
# Native PAP and EAP-MSCHAPv2 checks using synthetic users in a disposable image.
set -euo pipefail
agent_image="${1:?Usage: smoke_radius_passwords.sh <radius-agent-image>}"
image="netadmin-password-smoke-${RANDOM}"
trap 'docker image rm "$image" >/dev/null 2>&1 || true' EXIT
printf 'FROM %s\nRUN apk add --no-cache wpa_supplicant\n' "$agent_image" | docker build -q -t "$image" - >/dev/null
docker run --rm -i --network none --entrypoint python "$image" - <<'PY'
import os
import grp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import UTC, datetime, timedelta
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import subprocess
import time
from pathlib import Path

from netadmin.agents.radius import create_radius_agent, hash_password
from netadmin.services.radius_users import ManagedUser, PasswordHashes, managed_entries, render_users

root = Path('/etc/raddb')
managed = root / 'mods-config/files/netadmin'
authorize = root / 'mods-config/files/authorize'
os.chown(managed.parent, 0, grp.getgrnam('radius').gr_gid)
managed.parent.chmod(0o2770)
managed.write_text('')
authorize.write_text('$INCLUDE ' + str(managed) + '\n')
(root / 'clients.conf').write_text('client smoke { ipaddr = 127.0.0.1\n secret = testing123\n}\n')
subprocess.run([str(root / 'certs/bootstrap')], check=True, capture_output=True)
# The packaged bootstrap creates a server identity only; issue a disposable client identity.
ca = x509.load_pem_x509_certificate((root / 'certs/ca.pem').read_bytes())
ca_key = serialization.load_pem_private_key((root / 'certs/ca.key').read_bytes(), b'whatever')
client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.now(UTC)
client_certificate = (x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'smoke')]))
    .issuer_name(ca.subject).public_key(client_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    .sign(ca_key, hashes.SHA256()))
(root / 'certs/client.pem').write_bytes(
    client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()) +
    client_certificate.public_bytes(serialization.Encoding.PEM))
os.environ.update(NETADMIN_AGENT_TOKEN='synthetic', RADIUS_RELOAD_COMMAND='/bin/true')
client = create_radius_agent().test_client()
auth = {'Authorization': 'Bearer synthetic'}
# Published NT hash vector confirms the algorithm and byte encoding independently.
assert hash_password('password', minimum_length=1).nt == '8846f7eaee8fb117ad06bdd830b7586c'
password = 'Synthetic-password-123'
response = client.post('/users', headers=auth, json={'username': 'smoke', 'password': password})
assert response.status_code == 200, response.json
pair = managed_entries(managed.read_text())['smoke'].passwords
assert pair.crypt.startswith('$6$') and len(pair.nt) == 32


def authenticate(password, eap, expected, pool=False):
    log = Path('/tmp/radius-smoke.log')
    with log.open('w') as output:
        daemon = subprocess.Popen(['/usr/sbin/radiusd', '-X'], stdout=output, stderr=output)
        try:
            for _ in range(100):
                if 'Ready to process requests' in log.read_text():
                    break
                assert daemon.poll() is None, log.read_text()[-4000:]
                time.sleep(0.05)
            else:
                raise AssertionError('RADIUS did not become ready')
            if eap:
                config = Path('/tmp/eapol.conf')
                method = eap if isinstance(eap, str) else 'MSCHAPV2'
                extra = ''
                if method in ('PEAP', 'TLS'):
                    server = x509.load_pem_x509_certificate((root / 'certs/server.pem').read_bytes())
                    name = server.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    extra = ' ca_cert="/etc/raddb/certs/ca.pem"\n subject_match="' + name + '"\n'
                if method == 'PEAP':
                    extra += ' phase2="auth=MSCHAPV2"\n'
                if method == 'TLS':
                    extra += (' client_cert="/etc/raddb/certs/client.pem"\n'
                              ' private_key="/etc/raddb/certs/client.pem"\n'
                              ' private_key_passwd="whatever"\n')
                config.write_text('network={\n key_mgmt=WPA-EAP\n eap=' + method + '\n'
                                  ' identity="smoke"\n password="' + password + '"\n' + extra + '}\n')
                result = subprocess.run(['/sbin/eapol_test', '-c', str(config), '-a127.0.0.1',
                                         '-p1812', '-stesting123', '-t5'],
                                        capture_output=True, text=True, timeout=15)
                accepted = result.returncode == 0 and 'SUCCESS' in result.stdout
            else:
                result = subprocess.run(['/usr/bin/radclient', '-x', '-r1', '-t2',
                                         '127.0.0.1:1812', 'auth', 'testing123'],
                                        input='User-Name = "smoke"\nUser-Password = "' + password + '"\n',
                                        capture_output=True, text=True, timeout=10)
                accepted = 'Received Access-Accept' in result.stdout
                assert 'Received Access-' in result.stdout, result.stdout + result.stderr
            assert accepted == expected, result.stdout + result.stderr + log.read_text()[-2000:]
            if pool:
                response_text = (log.read_text().rsplit('Sent Access-Accept', 1)[-1]
                                 if eap else result.stdout)
                assert 'Framed-Pool = "pool-smoke"' in response_text, response_text
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)


# Both stored together, then each format independently with the native daemon.
authenticate(password, False, True)
authenticate(password, True, True)
managed.write_text(render_users({'smoke': ManagedUser(PasswordHashes(pair.crypt), 'netadmin-standard')}))
authenticate(password, False, True)
managed.write_text(render_users({'smoke': ManagedUser(PasswordHashes(nt=pair.nt), 'netadmin-standard')}))
authenticate(password, True, True)
managed.write_text(render_users({'smoke': ManagedUser(pair, 'netadmin-standard')}))
new_password = 'Replacement-password-456'
response = client.post('/users/password', headers=auth,
                       json={'username': 'smoke', 'password': new_password})
assert response.status_code == 200, response.json
changed = managed_entries(managed.read_text())['smoke'].passwords
assert changed.crypt != pair.crypt and changed.nt != pair.nt
for eap in (False, True):
    authenticate(new_password, eap, True)
    authenticate(password, eap, False)
# Cleartext migration must retain native replies, then disabled users must fail.
managed.write_text('')
authorize.write_text('$INCLUDE ' + str(managed) + '\nsmoke Cleartext-Password := "' + password +
                     '"\n\tFramed-Pool = "pool-smoke"\n')
response = client.post('/migration', headers=auth, json={})
assert response.status_code == 200, response.json
assert 'Cleartext-Password' not in authorize.read_text() + managed.read_text()
authenticate(password, False, True, pool=True)
authenticate(password, True, True)
response = client.post('/users', headers=auth, json={'username': 'smoke', 'disabled': True})
assert response.status_code == 200, response.json
authenticate(password, False, False)
authenticate(password, True, False)
assert 'password' not in client.get('/users', headers=auth).json[0]
print('Native PAP and EAP-MSCHAPv2 passed: paired hashes, individual formats, reset, old-password rejection.')
# Mode changes must actually prevent disabled outer methods while retaining PEAP's inner method.
from netadmin.agents import radius_modes
radius_modes._protocol_ready = lambda: True
radius_modes._restart = lambda: None
client.application.config['RADIUS_AUTH_MANAGEMENT'] = True
client.post('/users', headers=auth, json={'username': 'smoke', 'disabled': False})

def select_modes(enabled, preferred):
    status = client.get('/authentication', headers=auth).json
    response = client.post('/authentication', headers=auth,
                           json={'enabled': enabled, 'preferred': preferred, 'revision': status['revision']})
    assert response.status_code == 200, response.json
    status = client.get('/authentication', headers=auth).json
    assert set(status['enabled']) == set(enabled), status
    assert status['uses_certificates'] == bool({'peap', 'tls'}.intersection(enabled)), status

select_modes(['peap'], 'peap')
authenticate(password, 'PEAP', True, pool=True)
authenticate(password, True, False)
authenticate(password, 'TLS', False)
select_modes(['tls'], 'tls')
authenticate(password, 'TLS', True)
authenticate(password, 'PEAP', False)
select_modes(['mschapv2', 'peap', 'tls'], 'peap')
for method in (True, 'PEAP', 'TLS'):
    authenticate(password, method, True)
select_modes(['mschapv2'], 'mschapv2')
authenticate(password, True, True)
authenticate(password, 'PEAP', False)
print('Authentication mode toggles passed: PEAP inner MSCHAPv2, EAP-TLS, coexistence, disabled-method rejection.')
PY
