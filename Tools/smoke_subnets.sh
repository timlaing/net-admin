#!/usr/bin/env bash
# Validate subnet CRUD with both real daemon parsers in the agent image.
set -euo pipefail
docker run --rm -i --network none --entrypoint python3 "${1:-netadmin-dhcp-agent:test}" - <<'PY'
import os
import tempfile
from pathlib import Path
from netadmin.agents.dhcp import create_dhcp_agent

for backend in ('isc','kea'):
    with tempfile.TemporaryDirectory() as directory:
        main = Path(directory)/'main.conf'
        main.write_text('authoritative;\n' if backend == 'isc' else
            '{"Dhcp4":{"interfaces-config":{"interfaces":[]},"lease-database":{"type":"memfile","persist":false},"valid-lifetime":3600,"subnet4":[]}}')
        os.environ.update(NETADMIN_AGENT_TOKEN='synthetic', DHCP_SERVER=backend,
                          DHCP_MAIN_CONFIG=str(main), DHCP_RELOAD_COMMAND='')
        client = create_dhcp_agent().test_client()
        auth = {'Authorization':'Bearer synthetic'}
        for cidr in ('192.0.2.0/24','198.51.100.0/24'):
            response = client.post('/subnets',headers=auth,json={'cidr':cidr})
            assert response.status_code == 201, (backend,response.json)
        assert len(client.get('/configuration',headers=auth).json) == 2
        response = client.post('/subnets/delete',headers=auth,json={'network':'192.0.2.0'})
        assert response.status_code == 200, (backend,response.json)
        assert client.get('/configuration',headers=auth).json[0]['network'] == '198.51.100.0'
        print(backend + ': real daemon validation of creation/removal passed')
PY
