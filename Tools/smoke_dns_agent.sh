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
    # Dual-stack hostname with an IPv4-only Bind listener; no external DNS/network.
    with Path('/etc/hosts').open('a') as hosts:
        hosts.write('\n::1 bind-smoke.test\n127.0.0.1 bind-smoke.test\n')
    key = root / 'key.conf'
    key.write_text('key "test" { algorithm hmac-sha256; secret "YWJj"; };')
    rndc = 'include "' + str(key) + '"; options { default-server 127.0.0.1; default-key "test"; };'
    Path('/etc/bind/rndc.conf').write_text(rndc)
    Path('/etc/rndc.conf').write_text(rndc)
    main = root / 'named.conf'
    main.write_text('include "' + str(key) + '";\noptions { directory "' + directory + '"; '
        'listen-on port 9153 {127.0.0.1;}; listen-on-v6 {none;}; recursion no; '
        'dnssec-validation no; max-records-per-type 0; pid-file "' + directory + '/named.pid"; };'
        'controls { inet 127.0.0.1 port 953 allow {127.0.0.1;} keys {"test";}; };')
    daemon = subprocess.Popen(['/usr/sbin/named', '-g', '-c', str(main)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            if subprocess.run(['/usr/sbin/rndc','status'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise AssertionError('Bind control channel did not start')
        os.environ.update(NETADMIN_AGENT_TOKEN='synthetic', DNS_UPDATE_KEY='test', DNS_SERVER='bind-smoke.test', DNS_PORT='9153', DNS_MAIN_CONFIG=str(main),
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
        records = client.get('/records?zone=example.net', headers=headers)
        assert records.status_code == 200, records.json
        assert any(item['name'] == 'client' for item in records.json)
        # Read persisted zone data plus live journal updates without changing
        # transfer ACLs, syncing the daemon, or reconfiguring it.
        snapshot = client.get('/records?zone=example.net&source=file', headers=headers)
        assert snapshot.status_code == 200, snapshot.json
        assert any(item['name'] == 'client' and item['value'] == '192.0.2.2' for item in snapshot.json)
        record = {'zone':'example.net','name':'agent-client','record_type':'A','ttl':600,'value':'192.0.2.3'}
        assert client.post('/records', headers=headers, json=record).status_code == 200
        records = client.get('/records?zone=example.net', headers=headers).json
        assert any(item['name'] == 'agent-client' and item['value'] == '192.0.2.3' and item['ttl'] == 600 for item in records)
        restored = {'zone':'example.net','name':'agent-client','record_type':'A','ttl':3600,'values':['192.0.2.10','192.0.2.11']}
        assert client.post('/records', headers=headers, json=restored).status_code == 200
        records = [item for item in client.get('/records?zone=example.net', headers=headers).json if item['name']=='agent-client']
        assert {item['value'] for item in records} == {'192.0.2.10','192.0.2.11'}
        assert {item['ttl'] for item in records} == {3600}
        record.pop('value')
        assert client.post('/records/delete', headers=headers, json=record).status_code == 200
        assert not any(item['name'] == 'agent-client' for item in client.get('/records?zone=example.net', headers=headers).json)
        assert client.get('/records?zone=unmanaged.example', headers=headers).status_code == 400
        original = (root/'managed.conf').read_bytes()
        assert client.post('/zones', headers=headers, json={'name':'bad.example','content':'invalid zone'}).status_code == 502
        assert (root/'managed.conf').read_bytes() == original
        # Paired writes must work with authoritative queries when AXFR is denied.
        managed = root/'managed.conf'
        config = managed.read_text()
        restricted = config.replace('allow-transfer { key "test"; };', 'allow-transfer { none; };')
        assert restricted != config
        managed.write_text(restricted)
        subprocess.run(['/usr/bin/named-checkconf',str(main)],check=True)
        subprocess.run(['/usr/sbin/rndc','reconfig'],check=True,capture_output=True)
        assert client.get('/records?zone=example.net',headers=headers).status_code == 502
        old_addresses = [f'192.0.2.{index}' for index in range(1,102)]
        restore = {'zone':'example.net','name':'MiXeD','record_type':'A','ttl':0,'values':old_addresses}
        large = client.post('/records',headers=headers,json=restore)
        assert large.status_code == 200,large.json
        from types import SimpleNamespace
        from netadmin.services.dns import AgentDnsService
        def get(path):
            result = client.get('/'+path,headers=headers)
            assert result.status_code == 200,result.json
            return result.json
        def post(path,payload):
            result = client.post('/'+path,headers=headers,json=payload)
            if result.status_code >= 400:
                raise RuntimeError(f"Synthetic agent request rejected: {payload.get('record_type', 'unknown')}")
            return result.json
        paired = AgentDnsService(SimpleNamespace(get=get,post=post))
        try:
            paired.add_host('mixed','192.0.2.200','example.net','2.0.192.in-addr.arpa',600)
        except RuntimeError as error:
            assert str(error).endswith(': PTR'),str(error)
        else:
            raise AssertionError('Unconfigured reverse zone unexpectedly accepted')
        saved = get('records/addresses?zone=example.net&name=mixed')
        assert {item['value'] for item in saved} == set(old_addresses)
        assert {item['ttl'] for item in saved} == {0}
        current = {'zone':'example.net','name':'mixed','record_type':'A','ttl':600,'value':'192.0.2.200'}
        assert client.post('/records',headers=headers,json=current).status_code == 200
        concurrent = dns.update.Update('example.net',keyring=dns.tsigkeyring.from_text({'test':'YWJj'}))
        concurrent.add('mixed',600,'A','192.0.2.201')
        assert dns.query.tcp(concurrent,'127.0.0.1',port=9153,timeout=5).rcode()==0
        assert client.post('/records',headers=headers,json={**restore,'expected':'192.0.2.200'}).status_code==502
        assert {item['value'] for item in get('records/addresses?zone=example.net&name=mixed')}=={'192.0.2.200','192.0.2.201'}
        assert client.post('/records',headers=headers,json=current).status_code == 200
        assert client.post('/records',headers=headers,json={**restore,'values':[],'expected':'192.0.2.200'}).status_code==200
        assert get('records/addresses?zone=example.net&name=mixed')==[]
        print('AXFR denied: mixed-case paired rollback restored 101 zero-TTL addresses; prerequisite preserved concurrent writes')
        assert client.post('/zones/delete', headers=headers, json={'name':'example.net'}).status_code == 200
        assert (root/'zones/example.net.zone').exists()
        os.environ['NETADMIN_AGENT_READ_ONLY'] = 'true'
        assert client.get('/capabilities', headers=headers).json['read_only'] is True
        assert client.post('/zones', headers=headers, json={'name':'blocked.example','content':zone}).status_code == 403
        print('Real Bind hostname transport, discovery, zone lifecycle, agent record reads/updates/deletes and rollback passed')
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
PY
