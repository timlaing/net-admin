"""Exercise fresh service selections in isolated bridge networks, without host ports.

Requires the development environment and images named netadmin-*:installer-smoke.
On native Linux, run with sudo to match the installer's service-file ownership.
Every deployment, volume and credential created here is disposable and synthetic.
"""

import importlib.util
import ipaddress
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer", ROOT / "scripts/install_services.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
real_run = installer.run


def run(args, **kwargs):
    """Use local smoke images while exercising the real installer functions."""
    args = [
        argument.replace("ghcr.io/timlaing/", "").replace(":0.0.0-smoke", ":installer-smoke")
        for argument in map(str, args)
    ]
    return real_run(args, **kwargs)


installer.run = run


def execute(directory, service, code):
    """Never put synthetic credentials in command arguments or tool output."""
    return installer.compose(
        directory, "exec", "-T", service, "python3", "-c", code, capture_output=True
    )


def authenticated(directory, state):
    """Verify TLS identity and bearer authentication inside each isolated agent."""
    services = []
    if state["dns"] == "yes":
        services.append(("dns-agent", 8083))
    if state["dhcp"] != "none":
        services.append((f"dhcp-agent-{state['dhcp']}", 8081))
    if state["radius"] == "yes":
        services.append(("radius-agent", 8082))
    if state["ca"] == "yes":
        services.append(("ca-agent", 8084))
    for service, port in services:
        code = f"""
import os, ssl, urllib.request, urllib.error
context = ssl.create_default_context(cafile='/test-client/ca.crt')
context.load_cert_chain('/test-client/client.crt', '/test-client/client.key')
url = 'https://127.0.0.1:{port}/capabilities'
auth = {{'Authorization': 'Bearer ' + os.environ['NETADMIN_AGENT_TOKEN']}}
request = urllib.request.Request(url, headers=auth)
with urllib.request.urlopen(request, context=context, timeout=3) as response:
    assert response.status == 200
try:
    urllib.request.urlopen(url, context=context, timeout=3)
    raise AssertionError('Missing bearer token was accepted')
except urllib.error.HTTPError as error:
    assert error.code == 401
"""
        for attempt in range(30):
            try:
                execute(directory, service, code)
                break
            except Exception:
                if attempt == 29:
                    raise
                time.sleep(1)


def mutations(directory, state):
    """Use real agent transactions and daemon validation/reload for fresh CRUD."""
    if state["dns"] == "yes":
        execute(
            directory,
            "dns-agent",
            """
import os
from netadmin.agents.dns import create_dns_agent
client=create_dns_agent().test_client()
auth={'Authorization': 'Bearer '+os.environ['NETADMIN_AGENT_TOKEN']}
zone=('$ORIGIN fresh.example.test.\\n$TTL 3600\\n'
      '@ IN SOA ns.fresh.example.test. hostmaster.fresh.example.test. '
      '(1 3600 900 604800 3600)\\n@ IN NS ns.fresh.example.test.\\nns IN A 192.0.2.10\\n')
response=client.post('/zones', headers=auth, json={'name':'fresh.example.test','content':zone})
assert response.status_code == 201, response.json
response=client.post('/zones/delete', headers=auth, json={'name':'fresh.example.test'})
assert response.status_code == 200, response.json
""",
        )
    if state["dhcp"] != "none":
        backend = state["dhcp"]
        container = (
            installer.compose(directory, "ps", "-q", f"dhcp-{backend}", capture_output=True)
            .stdout.decode()
            .strip()
        )
        networks = json.loads(
            run(
                ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
                capture_output=True,
            ).stdout
        )
        network = next(iter(networks.values()))
        subnet = str(
            ipaddress.ip_network(f"{network['IPAddress']}/{network['IPPrefixLen']}", strict=False)
        )
        execute(
            directory,
            f"dhcp-agent-{backend}",
            f"""
import os
from netadmin.agents.dhcp import create_dhcp_agent
client=create_dhcp_agent().test_client()
auth={{'Authorization': 'Bearer '+os.environ['NETADMIN_AGENT_TOKEN']}}
response=client.post('/subnets', headers=auth, json={{'cidr':{subnet!r}}})
assert response.status_code == 201, response.json
response=client.post('/subnets/delete', headers=auth, json={{'network':{subnet.split("/")[0]!r}}})
assert response.status_code == 200, response.json
""",
        )
    if state["radius"] == "yes":
        execute(
            directory,
            "radius-agent",
            "from pathlib import Path; assert Path('/etc/raddb/certs/.netadmin-control').is_file()",
        )
        installer.native_validation(directory, {**state, "dns": "no", "dhcp": "none"})
        execute(
            directory,
            "radius-agent",
            "from pathlib import Path; assert Path('/etc/raddb/certs/.netadmin-control').is_file()",
        )
        execute(
            directory,
            "radius-agent",
            """
import os
from netadmin.agents.radius import create_radius_agent
client=create_radius_agent().test_client()
auth={'Authorization': 'Bearer '+os.environ['NETADMIN_AGENT_TOKEN']}
body={'name':'smoke-client','address':'192.0.2.50','secret':'synthetic-smoke-secret-12345'}
response=client.post('/clients', headers=auth, json=body)
assert response.status_code in (200,201), response.json
""",
        )
    if state["ca"] == "yes":
        installer.compose(
            directory,
            "exec",
            "-T",
            "ca-runtime",
            "python",
            "-c",
            """
import os, httpx
from pathlib import Path
client=httpx.Client(transport=httpx.HTTPTransport(uds='/control/ca.sock'))
token=Path(os.environ['CA_MANAGEMENT_TOKEN_FILE']).read_text().strip()
response=client.get('http://controller/authorities',headers={'X-CA-Management-Token':token})
response.raise_for_status()
""",
            capture_output=True,
        )


def host_bootstrap(distro):
    """Exercise host branches with mocked package managers in an isolated container."""
    script = r"""
set -eu
mkdir -p /mock /etc/yum.repos.d
printf 'ID=__DISTRO__\nVERSION_CODENAME=bookworm\n' > /etc/os-release
rm -f /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources
rm -f /etc/yum.repos.d/docker-ce.repo
cat > /mock/packages <<'PACKAGES'
#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> /calls
case " $* " in
  *' docker-ce '*)
    cat > /mock/docker <<'DOCKER'
#!/bin/sh
case "$*" in 'compose version') exit 0;; *) exit 1;; esac
DOCKER
    chmod +x /mock/docker
    ;;
esac
PACKAGES
cat > /mock/curl <<'CURL'
#!/bin/sh
printf 'curl %s\n' "$*" >> /calls
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then printf 'synthetic signing key' > "$2"; exit 0; fi
  shift
done
exit 1
CURL
printf '#!/bin/sh\nexit 1\n' > /mock/rpm
printf '#!/bin/sh\nprintf "systemctl %%s\\n" "$*" >> /calls\n' > /mock/systemctl
chmod +x /mock/*
ln -s packages /mock/apt-get
ln -s packages /mock/dnf
export PATH=/mock:$PATH
if bash /installer --yes --address 192.0.2.10 --dns no --dhcp none \
  --radius no --ca yes > /out 2>&1; then
  echo 'Bootstrap unexpectedly succeeded past the mock Docker daemon' >&2
  exit 1
fi
grep -q 'Docker is installed but unavailable' /out || { cat /out; exit 1; }
cat /calls
""".replace("__DISTRO__", distro)
    response = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "bash",
            "--volume",
            f"{ROOT / 'scripts/install.sh'}:/installer:ro",
            "netadmin-dhcp-agent:installer-smoke",
            "-c",
            script,
        ],
        capture_output=True,
    )
    commands = response.stdout.decode()
    assert (
        "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
        in commands
    )
    assert "systemctl enable --now docker" in commands
    assert " remove " not in commands and " purge " not in commands
    if distro in {"ubuntu", "debian", "raspbian"}:
        expected = "ubuntu" if distro == "ubuntu" else "debian"
        assert f"https://download.docker.com/linux/{expected}/gpg" in commands
    elif distro == "fedora":
        assert (
            "config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo"
            in commands
        )
    else:
        assert (
            "config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo"
            in commands
        )
    print(f"PASS: {distro} package/repository setup with mocked host tools", flush=True)


def main():
    """No host networking, host ports or production state is used by these tests."""
    if sys.platform == "linux" and os.geteuid() != 0:
        raise SystemExit(
            "Run this smoke test with sudo on Linux, matching the production installer."
        )
    installer.check_agents = authenticated
    for dns, dhcp, radius, ca in (
        ("yes", "isc", "yes", "yes"),
        ("no", "kea", "no", "no"),
        ("no", "none", "no", "yes"),
        ("no", "none", "yes", "no"),
    ):
        installer.PROJECT = "netadmin-install-smoke-" + uuid.uuid4().hex[:10]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "deployment"
            args = SimpleNamespace(
                directory=directory,
                address="127.0.0.1",
                interface="eth0",
                dns=dns,
                dhcp=dhcp,
                radius=radius,
                ca=ca,
                version="0.0.0-smoke",
                source_directory=ROOT,
            )
            installer.prepare(args)
            template = yaml.safe_load((directory / "compose.yml").read_text())
            for name, service in template["services"].items():
                service["image"] = (
                    service["image"]
                    .replace("ghcr.io/timlaing/", "")
                    .replace("${NETADMIN_VERSION:?}", "installer-smoke")
                )
                service.pop("ports", None)
                if service.get("network_mode") == "host":
                    service.pop("network_mode")
                if name == "dns-agent":
                    service["network_mode"] = "service:dns"
                if "agent" in name:
                    service["volumes"].append("./transport/client:/test-client:ro")
            (directory / "compose.yml").write_text(yaml.safe_dump(template))
            # Production DNS listens on loopback plus its fixed LAN address.
            if dns == "yes":
                config = directory / "config/bind/named.conf"
                config.write_text(config.read_text().replace("127.0.0.1; 127.0.0.1;", "127.0.0.1;"))
            try:
                # Pulling is deliberately omitted: CI builds these local test images.
                state = json.loads((directory / "installation.json").read_text())
                if radius == "yes":
                    installer.seed_radius(directory, state)
                installer.native_validation(directory, state)
                installer.compose(directory, "up", "-d", "--no-build", capture_output=True)
                authenticated(directory, state)
                mutations(directory, state)
                print(f"PASS: DNS={dns}, DHCP={dhcp}, RADIUS={radius}, CA={ca}", flush=True)
            except Exception as error:
                # Report daemon errors but do not dump logs containing TSIG keys.
                print(type(error).__name__, str(error), flush=True)
                stderr = getattr(error, "stderr", b"")
                print(stderr.decode()[-5000:] if isinstance(stderr, bytes) else stderr, flush=True)
                raise
            finally:
                installer.compose(
                    directory, "down", "--volumes", "--remove-orphans", capture_output=True
                )
                # Files copied from the image can be root-owned in native Linux CI.
                if os.geteuid() != 0:
                    run(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "--network",
                            "none",
                            "--entrypoint",
                            "sh",
                            "--volume",
                            f"{directory}:/cleanup",
                            "netadmin-dns:installer-smoke",
                            "-c",
                            "chown -R " + str(os.getuid()) + ":" + str(os.getgid()) + " /cleanup",
                        ],
                        capture_output=True,
                    )
    for distro in ("ubuntu", "debian", "raspbian", "fedora", "rhel"):
        host_bootstrap(distro)


if __name__ == "__main__":
    main()
