"""Fresh installations select independent services and preserve failed state."""

import importlib.util
import itertools
import os
import shutil
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def installer():
    spec = importlib.util.spec_from_file_location(
        "services_installer", ROOT / "scripts/install_services.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def options(tmp_path, dns="yes", dhcp="kea", radius="yes", ca="yes"):
    return SimpleNamespace(
        directory=tmp_path / "installation",
        address="192.0.2.10",
        interface="eth0",
        dns=dns,
        dhcp=dhcp,
        radius=radius,
        ca=ca,
        version="0.0.0-test",
        source_directory=ROOT,
    )


@pytest.fixture
def port_probe(installer, monkeypatch):
    """Record scoped probes and simulate busy ports without reserving host ports."""
    state = SimpleNamespace(bindings=[], closed=0, occupied=set())

    class Probe:
        def __init__(self, family, kind):
            assert family == socket.AF_INET
            self.kind = kind

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            state.closed += 1

        def bind(self, target):
            binding = (*target, self.kind)
            state.bindings.append(binding)
            if binding in state.occupied:
                raise OSError("synthetic occupied port")

    monkeypatch.setattr(
        installer,
        "socket",
        SimpleNamespace(
            AF_INET=socket.AF_INET,
            SOCK_STREAM=socket.SOCK_STREAM,
            SOCK_DGRAM=socket.SOCK_DGRAM,
            socket=Probe,
        ),
    )
    return state


def test_port_probes_use_service_addresses_and_close_every_socket(installer, tmp_path, port_probe):
    args = options(tmp_path)
    installer.check_ports(args)
    bindings = set(port_probe.bindings)
    assert {host for host, _port, _kind in bindings} == {args.address, "127.0.0.1"}
    assert {port for host, port, _kind in bindings if host == "127.0.0.1"} == {53, 953}
    assert (args.address, 67, socket.SOCK_DGRAM) in bindings
    assert (args.address, 8081, socket.SOCK_STREAM) in bindings
    for host in (args.address, "127.0.0.1"):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            assert (host, 53, kind) in bindings
    assert port_probe.closed == len(port_probe.bindings)


@pytest.mark.parametrize(
    "host,port,kind", [("127.0.0.1", 53, socket.SOCK_STREAM), ("192.0.2.10", 67, socket.SOCK_DGRAM)]
)
def test_busy_scoped_ports_still_abort_preflight(installer, tmp_path, port_probe, host, port, kind):
    port_probe.occupied.add((host, port, kind))
    with pytest.raises(ValueError, match=f"Required port {port} is already in use"):
        installer.check_ports(options(tmp_path))
    assert port_probe.closed == len(port_probe.bindings)


def test_ca_only_does_not_probe_other_services(installer, tmp_path, port_probe):
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")
    installer.check_ports(args)
    assert set(port_probe.bindings) == {
        (args.address, port, socket.SOCK_STREAM) for port in (8084, *range(9100, 9116))
    }
    assert port_probe.closed == len(port_probe.bindings)


CHOICES = [
    choice
    for choice in itertools.product(
        ("yes", "no"), ("isc", "kea", "none"), ("yes", "no"), ("yes", "no")
    )
    if choice != ("no", "none", "no", "no")
]


@pytest.mark.parametrize("dns,dhcp,radius,ca", CHOICES)
def test_selected_services_have_no_unselected_dependencies(
    installer, tmp_path, monkeypatch, dns, dhcp, radius, ca
):
    args = options(tmp_path, dns, dhcp, radius, ca)
    installer.validate(args, host=False)
    # Use actual Compose config when available; this operation needs no daemon.
    if not shutil.which("docker"):
        monkeypatch.setattr(installer, "compose", lambda *_args, **_kwargs: None)
    installer.prepare(args)
    env = dict(line.split("=", 1) for line in (args.directory / ".env").read_text().splitlines())
    profiles = set(env["COMPOSE_PROFILES"].split(","))
    definition = yaml.safe_load((args.directory / "compose.yml").read_text())
    selected = {
        name: service
        for name, service in definition["services"].items()
        if profiles.intersection(service["profiles"])
    }
    expected = set()
    if dns == "yes":
        expected.update(("dns", "dns-agent"))
    if dhcp != "none":
        expected.update((f"dhcp-{dhcp}", f"dhcp-agent-{dhcp}"))
    if radius == "yes":
        expected.update(("radius", "radius-agent"))
    if ca == "yes":
        expected.update(("ca-runtime", "ca-agent"))
    assert selected.keys() == expected
    for service in selected.values():
        assert set(service.get("depends_on", [])).issubset(expected)
        assert service["image"].startswith("ghcr.io/timlaing/netadmin-")
        assert "build" not in service
    assert (args.directory / "config/bind").exists() == (dns == "yes")
    assert (args.directory / "config/dhcp").exists() == (dhcp != "none")
    assert (args.directory / "secrets/management-token").exists() == (ca == "yes")
    for name, enabled in (
        ("dns", dns == "yes"),
        ("dhcp", dhcp != "none"),
        ("radius", radius == "yes"),
        ("ca", ca == "yes"),
    ):
        assert (args.directory / "transport" / name).exists() == enabled


def test_transport_credentials_are_valid_private_and_distinct(installer, tmp_path):
    args = options(tmp_path)
    installer.prepare(args)
    directory = args.directory
    for relative in (
        "agents.env",
        ".env",
        "transport/authority/ca.key",
        "transport/client/client.key",
        "secrets/management-token",
    ):
        assert (directory / relative).stat().st_mode & 0o077 == 0
    client = x509.load_pem_x509_certificate(
        (directory / "transport/client/client.crt").read_bytes()
    )
    server = x509.load_pem_x509_certificate((directory / "transport/ca/server.crt").read_bytes())
    assert (
        ExtendedKeyUsageOID.CLIENT_AUTH
        in client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert (
        ExtendedKeyUsageOID.SERVER_AUTH
        in server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    assert client.public_key() != server.public_key()
    verify = installer.run(
        [
            "openssl",
            "verify",
            "-x509_strict",
            "-CAfile",
            str(directory / "transport/client/ca.crt"),
            "-verify_ip",
            args.address,
            str(directory / "transport/ca/server.crt"),
        ],
        capture_output=True,
    )
    assert verify.returncode == 0
    assert not (directory / "root.key").exists()
    assert list((directory / "config/bind/zones").iterdir()) == []
    assert '"subnet4": []' in (directory / "config/dhcp/kea4.conf").read_text()


def test_preparation_failure_does_not_leave_or_replace_keys(installer, tmp_path, monkeypatch):
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic validation failure")

    monkeypatch.setattr(installer, "compose", fail)
    with pytest.raises(RuntimeError, match="synthetic"):
        installer.prepare(args)
    assert not args.directory.exists()
    args.directory.mkdir()
    marker = args.directory / "keep.key"
    marker.write_text("synthetic original")
    with pytest.raises(ValueError, match="no files overwritten"):
        installer.validate(args, host=False)
    assert marker.read_text() == "synthetic original"


@pytest.mark.parametrize("failure", ["pull", "validation", "authentication"])
def test_startup_failure_preserves_credentials_and_never_reports_success(
    installer, tmp_path, monkeypatch, capsys, failure
):
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")
    installer.prepare(args)
    key = (args.directory / "transport/client/client.key").read_bytes()
    calls = []

    def call(_directory, *command, **_kwargs):
        calls.append(command)
        if command == ("pull",) and failure == "pull":
            raise RuntimeError("pull failed")

    def validation(*_args):
        if failure == "validation":
            raise RuntimeError("daemon validation failed")

    def authentication(*_args):
        raise RuntimeError("authentication failed")

    monkeypatch.setattr(installer, "compose", call)
    monkeypatch.setattr(installer, "native_validation", validation)
    monkeypatch.setattr(installer, "check_agents", authentication)
    with pytest.raises(RuntimeError):
        installer.main(["--directory", str(args.directory), "--resume"])
    captured = capsys.readouterr()
    assert "preserved" in captured.err
    assert "verified" not in captured.out
    assert (args.directory / "transport/client/client.key").read_bytes() == key
    assert (("up", "-d", "--no-build") in calls) == (failure == "authentication")


def test_resume_starts_only_saved_services_without_rotating_credentials(
    installer, tmp_path, monkeypatch
):
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")
    installer.prepare(args)
    before = {p: p.read_bytes() for p in args.directory.rglob("*") if p.is_file()}
    calls = []
    monkeypatch.setattr(
        installer, "compose", lambda _directory, *args, **_kwargs: calls.append(args)
    )
    monkeypatch.setattr(installer, "check_agents", lambda *_args: None)
    installer.main(["--directory", str(args.directory), "--resume"])
    assert calls == [("config", "--quiet"), ("pull",), ("up", "-d", "--no-build")]
    assert before == {p: p.read_bytes() for p in args.directory.rglob("*") if p.is_file()}


def test_inherited_compose_selectors_cannot_change_installation(installer, tmp_path, monkeypatch):
    monkeypatch.setenv("COMPOSE_PROFILES", "isc,kea,radius,ca,dns")
    monkeypatch.setenv("INSTALL_ADDRESS", "198.51.100.99")
    monkeypatch.setenv("NETADMIN_VERSION", "wrong")
    calls = []
    monkeypatch.setattr(installer, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    installer.compose(tmp_path, "config", "--quiet")
    assert "COMPOSE_PROFILES" not in calls[0][1]["env"]
    assert "INSTALL_ADDRESS" not in calls[0][1]["env"]
    assert "NETADMIN_VERSION" not in calls[0][1]["env"]
    assert calls[0][0][-2:] == ["config", "--quiet"]


@pytest.mark.parametrize(
    "flags",
    [
        ["--dns", "no", "--dhcp", "none", "--radius", "no", "--ca", "yes"],
        ["--dns", "no", "--dhcp", "none", "--radius", "yes", "--ca", "no"],
    ],
)
def test_launcher_dry_run_is_non_mutating(tmp_path, flags):
    target = tmp_path / "new deployment"
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--dry-run",
            "--address",
            "192.0.2.10",
            "--directory",
            str(target),
            *flags,
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert "No packages, downloads, files or containers changed" in result.stdout
    assert not target.exists()


def test_no_services_is_rejected_before_preparation(installer, tmp_path):
    args = options(tmp_path, "no", "none", "no", "no")
    with pytest.raises(ValueError, match="at least one"):
        installer.validate(args, host=False)


def test_launcher_accepts_script_from_pipeline(tmp_path):
    target = tmp_path / "piped installation"
    response = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            "-s",
            "--",
            "--yes",
            "--dry-run",
            "--address",
            "192.0.2.10",
            "--dns",
            "no",
            "--dhcp",
            "none",
            "--radius",
            "no",
            "--ca",
            "yes",
            "--directory",
            str(target),
        ],
        input=(ROOT / "scripts/install.sh").read_text(),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "DNS=no, DHCP=none, RADIUS=no, CA=yes" in response.stdout
    assert not target.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="Exercises the unprivileged sudo handoff")
def test_piped_sudo_handoff_preserves_selection_without_running_host_commands(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "uname").write_text(
        '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n'
    )
    (tools / "sudo").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE_ARGS"\ncp "$2" "$CAPTURE_SCRIPT"\n'
    )
    for tool in tools.iterdir():
        tool.chmod(0o700)
    args = tmp_path / "arguments"
    script = tmp_path / "elevated-script"
    marker = tmp_path / "must-not-execute"
    target = str(tmp_path / ("installation $(touch " + str(marker) + ")"))
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            "-s",
            "--",
            "--yes",
            "--address",
            "192.0.2.10",
            "--dns",
            "no",
            "--dhcp",
            "none",
            "--radius",
            "yes",
            "--ca",
            "no",
            "--directory",
            target,
        ],
        input=(ROOT / "scripts/install.sh").read_text(),
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "CAPTURE_ARGS": str(args),
            "CAPTURE_SCRIPT": str(script),
        },
        check=True,
    )
    assert result.returncode == 0
    handed_off = args.read_text().splitlines()
    assert handed_off[0] == "/bin/bash"
    assert handed_off[handed_off.index("--directory") + 1] == target
    assert "--interface" not in handed_off
    assert 'install_main "$@"' in script.read_text()
    assert not marker.exists()


def test_kea_publication_has_both_architectures_and_existing_smoke():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    entries = workflow["jobs"]["publish"]["strategy"]["matrix"]["include"]
    kea = [entry for entry in entries if entry["flavour"] == "dhcp-kea"]
    assert {entry["arch"] for entry in kea} == {"amd64", "aarch64"}
    for entry in kea:
        assert (ROOT / entry["smoke"]).is_file()
    assert "'-dhcp-kea'" in workflow["jobs"]["manifests"]["steps"][1]["run"]
