"""Validate Desktop port-publishing topology using disposable local images."""

import importlib.util
import json
import secrets
import socket
import ssl
import tempfile
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    """Let the host allocate an unused local TCP port for smoke isolation."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    """Start the Mac template without privileged host ports, then authenticate agents."""
    spec = importlib.util.spec_from_file_location(
        "mac_installer", ROOT / "scripts/install_services.py"
    )
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    original_run = installer.run

    def local_run(arguments, **kwargs):
        """Use already built test images without registry access."""
        return original_run(
            [
                item.replace("ghcr.io/timlaing/", "") if isinstance(item, str) else item
                for item in arguments
            ],
            **kwargs,
        )

    installer.run = local_run
    installer.PROJECT = "netadmin-mac-smoke-" + secrets.token_hex(5)
    with tempfile.TemporaryDirectory(prefix="netadmin-mac-smoke-", dir="/tmp") as temporary:
        directory = Path(temporary) / "deployment"
        args = SimpleNamespace(
            directory=directory,
            source_directory=ROOT,
            platform="macos",
            dns="yes",
            dhcp="none",
            radius="yes",
            ca="yes",
            version="installer-smoke",
            address="127.0.0.1",
            interface="",
        )
        installer.prepare(args)
        configuration = yaml.safe_load((directory / "compose.yml").read_text())
        mappings = {}
        for name, service in configuration["services"].items():
            service["image"] = service["image"].replace("ghcr.io/timlaing/", "")
            ports = []
            for entry in service.get("ports", []):
                target = entry.split(":")[-1]
                if "-" in target:
                    continue  # No issued CA listeners are needed for agent enrollment.
                port = free_port()
                ports.append(f"127.0.0.1:{port}:{target}")
                if target in {"8083", "8082", "8084"}:
                    mappings[name] = port
            if ports:
                service["ports"] = ports
            else:
                service.pop("ports", None)
        (directory / "compose.yml").write_text(yaml.safe_dump(configuration, sort_keys=False))
        try:
            state = json.loads((directory / "installation.json").read_text())
            installer.seed_radius(directory, state)
            installer.native_validation(directory, state)
            installer.compose(directory, "up", "-d", "--no-build")
            installer.check_daemons(directory, state)
            context = ssl.create_default_context(cafile=str(directory / "transport/client/ca.crt"))
            context.load_cert_chain(
                directory / "transport/client/client.crt", directory / "transport/client/client.key"
            )
            token = (directory / "agents.env").read_text().splitlines()[0].split("=", 1)[1]

            for name, port in mappings.items():
                for attempt in range(30):
                    try:
                        request = urllib.request.Request(
                            f"https://127.0.0.1:{port}/capabilities",
                            headers={"Authorization": "Bearer " + token},
                        )
                        with urllib.request.urlopen(  # noqa: S310 - fixed loopback HTTPS URL
                            request, context=context, timeout=3
                        ) as response:
                            assert response.status == 200
                        print(f"PASS: Mac topology {name} mTLS and published port")
                        break
                    except OSError:
                        if attempt == 29:
                            raise
                        time.sleep(1)
        finally:
            installer.compose(directory, "down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
