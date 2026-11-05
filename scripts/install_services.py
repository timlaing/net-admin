"""Prepare and start a release-pinned fresh-host service deployment (stdlib only)."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess  # nosec B404 - fixed executable/argument lists, never shell input
import sys
import time
import urllib.request
from pathlib import Path

PROJECT = "netadmin-services"
ASSETS = {
    "deployment/compose.yml": "compose.yml",
    "netadmin/pairing_exchange.py": "bootstrap/pairing.py",
    "deployment/isc-supervisor.sh": "bootstrap/isc-supervisor.sh",
    "deployment/reload-isc.py": "bootstrap/reload-isc.py",
    "deployment/radius-check.sh": "bootstrap/radius-check.sh",
    "scripts/install_services.py": "bootstrap/install_services.py",
}


def run(args, **kwargs):
    """Do not pass operator data through a shell or print command credentials."""
    kwargs.setdefault("timeout", 900)
    return subprocess.run(args, check=True, **kwargs)  # noqa: S603


def compose(directory, *args, **kwargs):
    """Never depend on the invoking shell's directory or Compose project."""
    environment = os.environ.copy()
    for name in (
        "COMPOSE_PROFILES",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "NETADMIN_VERSION",
        "INSTALL_ADDRESS",
        "DHCP_INTERFACE",
        "NETADMIN_DNS_TSIG_SECRET",
    ):
        environment.pop(name, None)
    return run(
        [
            "docker",
            "compose",
            "--project-name",
            PROJECT,
            "--project-directory",
            str(directory),
            "--env-file",
            str(directory / ".env"),
            "-f",
            str(directory / "compose.yml"),
            *args,
        ],
        env=environment,
        **kwargs,
    )


def write(directory, name, content, mode=0o600):
    """All credential files start private, including during preparation."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def download(version, name):
    """Fetch template/code only from the selected repository release tag."""
    url = f"https://raw.githubusercontent.com/timlaing/net-admin/v{version}/{name}"
    with urllib.request.urlopen(url, timeout=30) as response:
        content = response.read(1_048_577)
    if len(content) > 1_048_576:
        raise ValueError("Deployment asset exceeds size limit")
    return content.decode("utf-8")


def host_platform():
    """Select the actual host instead of trusting a saved deployment or caller flag."""
    return "macos" if sys.platform == "darwin" else "linux"


def validate_engine(platform):
    """Reject remote contexts before contacting an engine or starting any service."""
    context = json.loads(
        run(["docker", "context", "inspect"], capture_output=True, timeout=10).stdout
    )
    endpoint = context[0]["Endpoints"]["docker"]["Host"]
    if not os.environ.get("DOCKER_CONTEXT"):
        endpoint = os.environ.get("DOCKER_HOST") or endpoint
    if not endpoint.startswith("unix://"):
        raise ValueError("Remote Docker contexts are not supported")
    info = json.loads(
        run(["docker", "info", "--format", "{{json .}}"], capture_output=True, timeout=10).stdout
    )
    if info.get("OSType") != "linux" or any(
        "rootless" in item for item in info.get("SecurityOptions", [])
    ):
        raise ValueError("Use a local, rootful Linux Docker Engine")
    if platform == "macos" and "Docker Desktop" not in info.get("OperatingSystem", ""):
        raise ValueError("macOS installation requires Docker Desktop")


def validate_resume(state):
    """Enforce host and endpoint constraints for saved deployments before Compose runs."""
    platform = host_platform()
    if state.get("platform", "linux") != platform:
        raise ValueError("Saved deployment platform does not match this host")
    if platform == "macos" and state.get("dhcp") != "none":
        raise ValueError("Saved macOS deployment cannot enable DHCP")
    validate_engine(platform)


def validate(args, *, host=True):
    """Reject unsafe input and host conflicts before touching deployment files."""
    macos = getattr(args, "platform", "linux") == "macos"
    if macos and args.dhcp != "none":
        raise ValueError("DHCP requires a native Linux host; select --dhcp none on macOS")
    if args.dns == "no" and args.dhcp == "none" and args.radius == "no" and args.ca == "no":
        raise ValueError("Select at least one service")
    address = ipaddress.IPv4Address(args.address)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("Use this host's fixed, non-loopback LAN IPv4 address")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", args.version):
        raise ValueError("Specify an explicit release version")
    if args.dhcp != "none" and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.interface):
        raise ValueError("Invalid LAN interface")
    if args.directory.exists() or args.directory.is_symlink():
        raise ValueError("Deployment directory exists; no files overwritten. Use --resume.")
    if not args.directory.is_absolute() or ".." in args.directory.parts:
        raise ValueError("Use an absolute deployment directory without traversal")
    if host:
        if ("macos" if macos else "linux") != host_platform():
            raise ValueError("Selected platform does not match this host")
        if macos:
            interface_data = run(["/sbin/ifconfig"], capture_output=True).stdout.decode()
            if not re.search(r"\binet " + re.escape(args.address) + r"\s", interface_data):
                raise ValueError("The selected address is not assigned to this Mac")
        else:
            addresses = json.loads(run(["ip", "-j", "-4", "addr"], capture_output=True).stdout)
            if not any(
                item.get("local") == args.address
                for link in addresses
                for item in link.get("addr_info", [])
            ):
                raise ValueError("The selected address is not assigned to this host")
            if args.dhcp != "none" and not any(
                link["ifname"] == args.interface for link in addresses
            ):
                raise ValueError("The selected DHCP interface does not exist")
        validate_engine("macos" if macos else "linux")
        running = run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"],
            capture_output=True,
        ).stdout.strip()
        if running:
            raise ValueError("An existing netadmin-services project was found; nothing replaced")
        check_ports(args)


def check_ports(args):
    """Fail before pulling/stopping anything if a selected listener is occupied."""
    ports = []
    if args.dns == "yes":
        ports += [(53, socket.SOCK_STREAM), (53, socket.SOCK_DGRAM), (8083, socket.SOCK_STREAM)]
        if getattr(args, "platform", "linux") != "macos":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                try:
                    listener.bind(("127.0.0.1", 953))
                except OSError as error:
                    raise ValueError("Local RNDC port 953 is already in use") from error
    if args.dhcp != "none":
        ports += [(67, socket.SOCK_DGRAM), (8081, socket.SOCK_STREAM)]
    if args.radius == "yes":
        ports += [(1812, socket.SOCK_DGRAM), (1813, socket.SOCK_DGRAM), (8082, socket.SOCK_STREAM)]
    if args.ca == "yes":
        ports += [(8084, socket.SOCK_STREAM)]
        ports += [(port, socket.SOCK_STREAM) for port in range(9100, 9116)]
    for port, kind in ports:
        # Desktop owns privileged host publishing; the desktop user cannot probe it.
        if getattr(args, "platform", "linux") == "macos" and port < 1024:
            continue
        hosts = [args.address]
        if port == 53 and getattr(args, "platform", "linux") != "macos":
            hosts.append("127.0.0.1")
        for host in hosts:
            # Probe only the intended service addresses, without listening.
            with socket.socket(socket.AF_INET, kind) as listener:
                try:
                    listener.bind((host, port))
                except OSError as error:
                    raise ValueError(
                        f"Required port {port} is already in use or unavailable"
                    ) from error


def certificates(directory, address, names):
    """Generate independent transport trust, not the user's managed service CA."""
    ca = directory / "transport/authority"
    ca.mkdir(parents=True)

    def openssl(*args):
        """Run certificate generation without exposing command output."""
        run(["openssl", *map(str, args)], capture_output=True)

    openssl(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-384",
        "-nodes",
        "-days",
        "3650",
        "-subj",
        "/CN=NetAdmin agent transport",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-addext",
        "authorityKeyIdentifier=keyid:always",
        "-keyout",
        ca / "ca.key",
        "-out",
        ca / "ca.crt",
    )
    for name in [*names, "client"]:
        target = directory / "transport" / name
        target.mkdir()
        identity = "client" if name == "client" else "server"
        extension = (
            "extendedKeyUsage=clientAuth\n"
            if name == "client"
            else (f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{address},DNS:{name}\n")
        )
        extension += (
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        )
        write(directory, f"transport/{name}/extensions.cnf", extension)
        openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-nodes",
            "-subj",
            f"/CN=netadmin-{name}",
            "-keyout",
            target / f"{identity}.key",
            "-out",
            target / "request.csr",
        )
        openssl(
            "x509",
            "-req",
            "-in",
            target / "request.csr",
            "-CA",
            ca / "ca.crt",
            "-CAkey",
            ca / "ca.key",
            "-set_serial",
            str(secrets.randbits(128) or 1),
            "-days",
            "365",
            "-extfile",
            target / "extensions.cnf",
            "-out",
            target / f"{identity}.crt",
        )
        shutil.copyfile(ca / "ca.crt", target / "ca.crt")
        (target / "request.csr").unlink()
        (target / "extensions.cnf").unlink()
        for path in target.iterdir():
            path.chmod(0o600)
    for path in ca.iterdir():
        path.chmod(0o600)


def initial_configuration(directory, args, tsig):
    """Seed valid empty configurations; zones and allocation pools belong in UI."""
    dns_listen = (
        "any" if getattr(args, "platform", "linux") == "macos" else f"127.0.0.1; {args.address}"
    )
    key = f'key "rndc-key" {{\n    algorithm hmac-sha256;\n    secret "{tsig}";\n}};\n'
    if args.dns == "yes":
        write(
            directory,
            "config/bind/named.conf",
            f"""include "/etc/bind/rndc.key";
    options {{
        directory "/etc/bind";
        listen-on {{ {dns_listen}; }};
        listen-on-v6 {{ none; }};
        recursion no;
        allow-transfer {{ none; }};
        pid-file "/run/named.pid";
    }};
    controls {{ inet 127.0.0.1 port 953 allow {{ 127.0.0.1; }} keys {{ "rndc-key"; }}; }};
    """,
        )
        (directory / "config/bind/zones").mkdir()
        write(directory, "config/bind/rndc.key", key)
    if args.dhcp == "none":
        return
    (directory / "leases").mkdir()
    write(directory, "config/dhcp/rndc.key", key)
    write(directory, "config/keys/rndc.key", key)
    if args.dhcp == "isc":
        write(
            directory,
            "config/dhcp/dhcpd.conf",
            """authoritative;
default-lease-time 3600;
max-lease-time 7200;
ddns-update-style none;
include "/etc/dhcp/rndc.key";
include "/etc/dhcp/netadmin-reservations.conf";
""",
        )
        write(directory, "config/dhcp/netadmin-reservations.conf", "# Managed by NetAdmin\n", 0o640)
        write(directory, "leases/dhcpd.leases", "")
    else:
        config = {
            "Dhcp4": {
                "interfaces-config": {"interfaces": [args.interface]},
                "control-sockets": [
                    {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl.sock"}
                ],
                "lease-database": {
                    "type": "memfile",
                    "persist": True,
                    "name": "/var/lib/kea/dhcp4.leases",
                },
                "valid-lifetime": 3600,
                "subnet4": [],
                "reservations": "NETADMIN_RESERVATIONS",
            }
        }
        text = json.dumps(config, indent=2).replace(
            '"NETADMIN_RESERVATIONS"', '<?include "/etc/dhcp/netadmin-reservations.json"?>'
        )
        write(directory, "config/dhcp/kea4.conf", text + "\n")
        write(directory, "config/dhcp/netadmin-reservations.json", "[]\n")


def prepare(args):
    """Do not leave a partially generated credential set after a preparation error."""
    assets = {}
    for source, target in ASSETS.items():
        if source == "deployment/compose.yml" and getattr(args, "platform", "linux") == "macos":
            source = "deployment/compose.macos.yml"
        assets[target] = (
            (args.source_directory / source).read_text()
            if args.source_directory
            else download(args.version, source)
        )
    directory = args.directory
    os.umask(0o077)
    directory.mkdir(parents=True, mode=0o700)
    try:
        for target, content in assets.items():
            write(
                directory,
                target,
                content,
                0o700 if target == "bootstrap/radius-check.sh" else 0o600,
            )
        names = []
        profiles = []
        if args.dhcp != "none":
            profiles.append(args.dhcp)
            names.append("dhcp")
        for name in ("dns", "radius", "ca"):
            if getattr(args, name) == "yes":
                profiles.append(name)
                names.append(name)
        token = secrets.token_urlsafe(48)
        tsig = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        write(
            directory,
            ".env",
            (
                f"NETADMIN_VERSION={args.version}\nINSTALL_ADDRESS={args.address}\n"
                f"DHCP_INTERFACE={args.interface or 'unused'}\n"
                f"COMPOSE_PROFILES={','.join(profiles)}\n"
                f"NETADMIN_DNS_TSIG_SECRET={tsig}\n"
            ),
        )
        # Desktop listeners bind inside its isolated VM; only explicit host ports publish.
        agent_bind = "0.0.0.0" if getattr(args, "platform", "linux") == "macos" else args.address  # noqa: S104
        write(
            directory,
            "agents.env",
            (f"NETADMIN_AGENT_TOKEN={token}\nAGENT_BIND_ADDRESS={agent_bind}\n"),
        )
        if args.ca == "yes":
            write(directory, "secrets/management-token", secrets.token_urlsafe(48))
        certificates(directory, args.address, names)
        initial_configuration(directory, args, tsig)
        state = {
            "platform": getattr(args, "platform", "linux"),
            "schema": 1,
            "project": PROJECT,
            "version": args.version,
            "address": args.address,
            "interface": args.interface,
            "dns": args.dns,
            "dhcp": args.dhcp,
            "radius": args.radius,
            "ca": args.ca,
        }
        write(directory, "installation.json", json.dumps(state, indent=2) + "\n")
        compose(directory, "config", "--quiet")
    except BaseException:
        shutil.rmtree(directory)
        raise


def seed_radius(directory, state):
    """Copy clean package defaults from the selected image, never from live files."""
    target = directory / "config/radius"
    marker = directory / "bootstrap/radius-initialized"
    if marker.exists():
        return
    if target.exists():
        raise ValueError("Incomplete RADIUS initialization; inspect config/radius before resuming")
    target.mkdir(parents=True)
    try:
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
                f"{target}:/seed:rw" + ("" if state.get("platform") == "macos" else ",z"),
                f"ghcr.io/timlaing/netadmin-radius:{state['version']}",
                "-c",
                "cp -a /etc/raddb/. /seed/ && chown -R root:radius /seed "
                "&& find /seed -type d -exec chmod 2750 {} +",
            ],
            capture_output=True,
        )
        write(directory, "config/radius/mods-config/files/authorize", "$INCLUDE netadmin\n", 0o640)
        write(
            directory, "config/radius/mods-config/files/netadmin", "# Managed by NetAdmin\n", 0o640
        )
        write(
            directory,
            "config/radius/clients.conf",
            "$INCLUDE /etc/raddb/netadmin-clients.conf\n",
            0o640,
        )
        write(
            directory,
            "config/radius/netadmin-clients.conf",
            "# Add RADIUS clients in NetAdmin\n",
            0o640,
        )
        write(directory, "bootstrap/radius-initialized", "1\n")
    except BaseException:
        shutil.rmtree(target)
        raise


def native_validation(directory, state):
    """Validate using the exact release's daemon parsers before starting listeners."""
    if state["dns"] == "yes":
        compose(
            directory,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "named-checkconf",
            "dns",
            "-z",
            "/etc/bind/named.conf",
        )
    if state["dhcp"] == "isc":
        compose(
            directory,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "dhcpd",
            "dhcp-isc",
            "-t",
            "-cf",
            "/etc/dhcp/dhcpd.conf",
        )
    elif state["dhcp"] == "kea":
        compose(
            directory,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "kea-dhcp4",
            "dhcp-kea",
            "-t",
            "/etc/dhcp/kea4.conf",
        )
    if state["radius"] == "yes":
        compose(
            directory,
            "run",
            "--rm",
            "--no-deps",
            "--volume",
            f"{directory}/bootstrap/radius-check.sh:/usr/local/bin/radius-supervisor.sh:ro,z",
            "radius",
        )


def check_agents(directory, state, *, attempts=30):
    """Check actual mTLS/token requests, not merely that a TCP port is open."""
    context = ssl.create_default_context(cafile=str(directory / "transport/client/ca.crt"))
    context.load_cert_chain(
        directory / "transport/client/client.crt", directory / "transport/client/client.key"
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    token = (
        (directory / "agents.env").read_text().split("NETADMIN_AGENT_TOKEN=", 1)[1].splitlines()[0]
    )
    ports = {"dns": 8083} if state["dns"] == "yes" else {}
    if state["dhcp"] != "none":
        ports["dhcp"] = 8081
    if state["radius"] == "yes":
        ports["radius"] = 8082
    if state["ca"] == "yes":
        ports["ca"] = 8084
    pending = dict(ports)
    for _ in range(attempts):
        for name, port in list(pending.items()):
            headers = {"Authorization": f"Bearer {token}"}
            path = "/capabilities"
            if name == "ca":
                path = "/authorities"
                headers["X-CA-Management-Token"] = (
                    (directory / "secrets/management-token").read_text().strip()
                )
            request = urllib.request.Request(
                f"https://{state['address']}:{port}{path}", headers=headers
            )
            try:
                with opener.open(request, timeout=2) as response:
                    if response.status == 200:
                        del pending[name]
            except (OSError, ValueError):
                pass
        if not pending:
            return
        time.sleep(1)
    raise RuntimeError("Authenticated agent checks failed: " + ", ".join(pending))


def check_daemons(directory, state, *, attempts=30):
    """Require selected containers and native daemons, including ISC's idle state."""
    selected = set()
    probes = {}
    if state["dns"] == "yes":
        selected.update(("dns", "dns-agent"))
        probes["dns"] = ["rndc", "-t", "3", "status"]
    if state["dhcp"] != "none":
        backend = state["dhcp"]
        selected.update((f"dhcp-{backend}", f"dhcp-agent-{backend}"))
        if backend == "kea":
            probes["dhcp-agent-kea"] = ["python3", "-m", "netadmin.agents.kea_ctrl", "status-get"]
        else:
            probes["dhcp-isc"] = [
                "sh",
                "-c",
                "if grep -Eq '^[[:space:]]*subnet[[:space:]]+[0-9]' /etc/dhcp/dhcpd.conf; "
                "then pidof dhcpd >/dev/null; fi",
            ]
    if state["radius"] == "yes":
        selected.update(("radius", "radius-agent"))
        probes["radius"] = ["pidof", "radiusd"]
    if state["ca"] == "yes":
        selected.update(("ca-runtime", "ca-agent"))
    pending = "container status"
    for attempt in range(attempts):
        try:
            pending = "container status"
            output = compose(
                directory, "ps", "--all", "--format", "json", capture_output=True, timeout=5
            ).stdout
            try:
                records = json.loads(output)
            except json.JSONDecodeError:
                records = [json.loads(line) for line in output.splitlines() if line.strip()]
            if isinstance(records, dict):
                records = [records]
            ready = {
                record["Service"]
                for record in records
                if record.get("State") == "running"
                and record.get("Health") in (None, "", "healthy")
            }
            missing = sorted(selected - ready)
            if missing:
                pending = ", ".join(missing)
                raise RuntimeError("Selected containers are not running")
            for service, command in probes.items():
                pending = service
                compose(directory, "exec", "-T", service, *command, capture_output=True, timeout=12)
            return
        except (subprocess.SubprocessError, OSError, ValueError, RuntimeError):
            if attempt + 1 < attempts:
                time.sleep(1)
    raise RuntimeError("Native service readiness checks failed: " + pending)


def start(directory):
    """Retain state for explicit resume if pulling or startup fails."""
    state = json.loads((directory / "installation.json").read_text())
    if state.get("schema") != 1 or state.get("project") != PROJECT:
        raise ValueError("Unrecognized installation manifest")
    validate_resume(state)
    compose(directory, "config", "--quiet")
    compose(directory, "pull")
    if state["radius"] == "yes":
        seed_radius(directory, state)
    native_validation(directory, state)
    compose(directory, "up", "-d", "--no-build")
    check_agents(directory, state)
    check_daemons(directory, state)
    print("Selected services started; native daemons and agent authentication verified.")
    print("Open the Home Assistant NetAdmin app and configure the selected services:")
    if state["dns"] == "yes":
        print(f"  DNS agent: https://{state['address']}:8083")
    if state["dhcp"] != "none":
        print(f"  DHCP agent: https://{state['address']}:8081 (backend {state['dhcp']})")
    if state["radius"] == "yes":
        print(f"  RADIUS agent: https://{state['address']}:8082")
    if state["ca"] == "yes":
        print(f"  CA agent: https://{state['address']}:8084")
    print(f"Credentials are in {directory}/agents.env and transport/client/.")
    print("Copy the client CA/certificate/key securely to /config/pki/ in Home Assistant.")
    print("Enter the existing agent token and those paths in Settings > Agent security.")
    if state["ca"] == "yes":
        print("The separate CA management token is in secrets/management-token.")
    print("No user zones or allocation pools were created. Configure them in NetAdmin.")
    if state["dns"] == "yes":
        print("DNS starts authoritative-only; recursive resolver configuration is not enabled.")
    print(
        "Pair without copying credentials: run this command, "
        "then paste its code into Settings > Pair installation:"
    )
    print(
        shlex.join(
            [
                "sudo",
                sys.executable,
                str(directory / "bootstrap/pairing.py"),
                "--directory",
                str(directory),
            ]
        )
    )
    print("Service traffic and write/reload operations still require functional validation.")


def main(argv=None):
    """Called by the host bootstrap after Docker and host dependencies are ready."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux", "macos"), default=host_platform())
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--address", default="")
    parser.add_argument("--interface", default="")
    parser.add_argument("--dns", choices=("yes", "no"), default="yes")
    parser.add_argument("--dhcp", choices=("isc", "kea", "none"), default="kea")
    parser.add_argument("--radius", choices=("yes", "no"), default="yes")
    parser.add_argument("--ca", choices=("yes", "no"), default="yes")
    parser.add_argument("--version", default="")
    parser.add_argument("--source-directory", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--pair", action="store_true", help="Offer one-time enrollment after startup"
    )
    args = parser.parse_args(argv)
    # Ignore inherited Compose selectors, which could otherwise select both backends.
    for name in ("COMPOSE_PROFILES", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME"):
        os.environ.pop(name, None)
    if not args.resume:
        validate(args)
        prepare(args)
    if args.prepare_only:
        print(f"Prepared {args.directory}; no containers started. Resume with:")
        print(
            shlex.join(
                (["sudo"] if args.platform != "macos" else [])
                + [
                    sys.executable,
                    str(args.directory / "bootstrap/install_services.py"),
                    "--directory",
                    str(args.directory),
                    "--resume",
                ]
                + (["--platform", "macos"] if args.platform == "macos" else [])
            )
        )
    else:
        try:
            start(args.directory)
            if args.pair:
                run(
                    [
                        sys.executable,
                        str(args.directory / "bootstrap/pairing.py"),
                        "--directory",
                        str(args.directory),
                    ],
                    timeout=620,
                )
        except Exception:
            print(
                f"Installation incomplete; files and keys preserved in {args.directory}.",
                file=sys.stderr,
            )
            print("Inspect Compose logs, then rerun the installer with --resume.", file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
