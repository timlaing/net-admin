#!/usr/bin/env bash
# Exercise real Bind validation and RNDC in an isolated, disposable container.
set -euo pipefail
docker run --rm -i --network none --entrypoint python "${1:-netadmin-dns-agent:test}" - <<'PY'
import os
import dns.query
import dns.tsigkeyring
import dns.update
import subprocess
import tempfile
import time
from pathlib import Path
from netadmin.agents.dns import create_dns_agent

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    key = root / 'key.conf'
    key.write_text('key "test" { algorithm hmac-sha256; secret "YWJj"; };')
    rndc = 'include "' + str(key) + '"; options { default-server 127.0.0.1; default-key "test"; };'
    Path('/etc/bind/rndc.conf').write_text(rndc)
    Path('/etc/rndc.conf').write_text(rndc)
    main = root / 'named.conf'
    main.write_text('include "' + str(key) + '";\noptions { directory "' + directory + '"; '
        'listen-on port 9153 {127.0.0.1;}; listen-on-v6 {none;}; recursion no; '
        'dnssec-validation no; pid-file "' + directory + '/named.pid"; };'
        'controls { inet 127.0.0.1 port 953 allow {127.0.0.1;} keys {"test";}; };')
    daemon = subprocess.Popen(['/usr/sbin/named', '-g', '-c', str(main)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            if subprocess.run(['/usr/sbin/rndc','status'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise AssertionError('Bind control channel did not start')
        os.environ.update(NETADMIN_AGENT_TOKEN='synthetic', DNS_UPDATE_KEY='test', DNS_MAIN_CONFIG=str(main),
                          DNS_MANAGED_CONFIG=str(root/'managed.conf'), DNS_ZONE_DIR=str(root/'zones'))
        client = create_dns_agent().test_client()
        headers = {'Authorization':'Bearer synthetic'}
        zone = '$TTL 300\n@ IN SOA ns.example.net. hostmaster.example.net. (1 3600 600 86400 300)\n@ IN NS ns.example.net.\nns IN A 192.0.2.1\n'
        response = client.post('/zones', headers=headers, json={'name':'example.net','content':zone})
        assert response.status_code == 201, response.json
        assert client.get('/zones', headers=headers).json[0]['name'] == 'example.net'
        update = dns.update.Update('example.net', keyring=dns.tsigkeyring.from_text({'test':'YWJj'}))
        update.add('client',300,'A','192.0.2.2')
        assert dns.query.tcp(update,'127.0.0.1',port=9153,timeout=5).rcode() == 0
        original = (root/'managed.conf').read_bytes()
        assert client.post('/zones', headers=headers, json={'name':'bad.example','content':'invalid zone'}).status_code == 502
        assert (root/'managed.conf').read_bytes() == original
        assert client.post('/zones/delete', headers=headers, json={'name':'example.net'}).status_code == 200
        assert (root/'zones/example.net.zone').exists()
        print('Real Bind discovery, creation, rollback and removal passed')
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
PY
