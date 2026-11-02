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
                config.write_text('network={\n key_mgmt=WPA-EAP\n eap=MSCHAPV2\n'
                                  ' identity="smoke"\n password="' + password + '"\n}\n')
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
                assert 'Framed-Pool = "pool-smoke"' in result.stdout
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
PY
