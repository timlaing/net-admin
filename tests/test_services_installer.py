"""Fresh installations select independent services and preserve failed state."""

import contextlib
import importlib.util
import itertools
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def installer(monkeypatch):
    """Load the standalone installer without invoking its command-line entry point."""
    spec = importlib.util.spec_from_file_location(
        "services_installer", ROOT / "scripts/install_services.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "host_platform", lambda: "linux")
    return module


@pytest.fixture(scope="session")
def compose_probe():
    """Probe the optional Compose plugin once, with a bounded wait."""
    docker = shutil.which("docker")
    if docker:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            return (
                subprocess.run(  # noqa: S603
                    [docker, "compose", "version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                ).returncode
                == 0
            )
    return False


@pytest.fixture
def compose_available(installer, monkeypatch, compose_probe):
    """Keep each preparation test independent of an optional Compose plugin."""
    monkeypatch.setattr(installer, "validate_engine", lambda _platform: None)
    if not compose_probe:
        monkeypatch.setattr(installer, "compose", lambda *_args, **_kwargs: None)


def options(tmp_path, dns="yes", dhcp="kea", radius="yes", ca="yes"):
    """Build a fresh service selection rooted in the temporary test directory."""
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
            """Record the socket kind without opening a host socket."""
            assert family == socket.AF_INET
            self.kind = kind

        def __enter__(self):
            """Return this synthetic socket for a preflight probe."""
            return self

        def __exit__(self, *_args):
            """Count cleanup even when binding fails."""
            state.closed += 1

        def bind(self, target):
            """Record requested bindings and simulate occupied service ports."""
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
    """Reserve only intended service addresses and release every preflight socket."""
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
    """Reject occupied service ports while closing all attempted probes."""
    args = options(tmp_path)
    port_probe.occupied.add((host, port, kind))
    with pytest.raises(ValueError, match=f"Required port {port} is already in use"):
        installer.check_ports(args)
    assert port_probe.closed == len(port_probe.bindings)


def test_ca_only_does_not_probe_other_services(installer, tmp_path, port_probe):
    """Check only CA ports when all other services are deselected."""
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
    installer, tmp_path, compose_available, dns, dhcp, radius, ca
):
    """Prepare each supported selection without pulling in deselected services."""
    args = options(tmp_path, dns, dhcp, radius, ca)
    installer.validate(args, host=False)
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


def test_transport_credentials_are_valid_private_and_distinct(
    installer, tmp_path, compose_available
):
    """Validate transport trust, credential separation and private file permissions."""
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
    """Keep failed preparation from leaving credentials or overwriting existing state."""
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")

    def fail(*_args, **_kwargs):
        """Simulate preparation validation failing before deployment is retained."""
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


@pytest.mark.parametrize("failure", ["pull", "validation", "authentication", "daemon"])
def test_startup_failure_preserves_credentials_and_never_reports_success(
    installer, tmp_path, monkeypatch, capsys, failure, compose_available
):
    """Retain recoverable state and withhold success when any startup phase fails."""
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")
    installer.prepare(args)
    key = (args.directory / "transport/client/client.key").read_bytes()
    calls = []

    def call(_directory, *command, **_kwargs):
        """Record Compose operations and inject a pull failure when selected."""
        calls.append(command)
        if command == ("pull",) and failure == "pull":
            raise RuntimeError("pull failed")

    def validation(*_args):
        """Simulate native configuration validation failure when selected."""
        if failure == "validation":
            raise RuntimeError("daemon validation failed")

    def authentication(*_args):
        """Simulate agent authentication failure when selected."""
        if failure == "authentication":
            raise RuntimeError("authentication failed")

    def daemons(*_args):
        """Simulate native daemon readiness failure when selected."""
        if failure == "daemon":
            raise RuntimeError("native daemon is not ready")

    monkeypatch.setattr(installer, "compose", call)
    monkeypatch.setattr(installer, "native_validation", validation)
    monkeypatch.setattr(installer, "check_agents", authentication)
    monkeypatch.setattr(installer, "check_daemons", daemons)
    with pytest.raises(RuntimeError):
        installer.main(["--directory", str(args.directory), "--resume"])
    captured = capsys.readouterr()
    assert "preserved" in captured.err
    assert "verified" not in captured.out
    assert (args.directory / "transport/client/client.key").read_bytes() == key
    assert (("up", "-d", "--no-build") in calls) == (failure in {"authentication", "daemon"})


def test_resume_starts_only_saved_services_without_rotating_credentials(
    installer, tmp_path, monkeypatch, compose_available
):
    """Resume the saved selection and retain its existing credentials."""
    args = options(tmp_path, dns="no", dhcp="none", radius="no", ca="yes")
    installer.prepare(args)
    before = {p: p.read_bytes() for p in args.directory.rglob("*") if p.is_file()}
    calls = []
    monkeypatch.setattr(
        installer, "compose", lambda _directory, *args, **_kwargs: calls.append(args)
    )
    monkeypatch.setattr(installer, "check_agents", lambda *_args: None)
    monkeypatch.setattr(installer, "check_daemons", lambda *_args: None)
    installer.main(["--directory", str(args.directory), "--resume"])
    assert calls == [("config", "--quiet"), ("pull",), ("up", "-d", "--no-build")]
    assert before == {p: p.read_bytes() for p in args.directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "backend,server,agent",
    [
        ("dns", "dns", "dns-agent"),
        ("kea", "dhcp-kea", "dhcp-agent-kea"),
    ],
)
@pytest.mark.parametrize("stopped", [True, False])
def test_agent_readiness_cannot_hide_failed_daemons(
    installer, tmp_path, monkeypatch, backend, server, agent, stopped
):
    """Reject missing or stopped daemons even when agent readiness succeeds."""
    state = {
        "dns": "yes" if backend == "dns" else "no",
        "dhcp": "kea" if backend == "kea" else "none",
        "radius": "no",
        "ca": "no",
    }
    records = [
        {"Service": server, "State": "exited" if stopped else "running"},
        {"Service": agent, "State": "running"},
    ]
    calls = []

    def command(_directory, *args, **_kwargs):
        """Supply synthetic Compose status or reject native daemon commands."""
        calls.append(args)
        if args[:1] == ("ps",):
            return SimpleNamespace(stdout=json.dumps(records))
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(installer, "compose", command)
    with pytest.raises(RuntimeError, match="Native service readiness checks failed"):
        installer.check_daemons(tmp_path, state, attempts=1)
    if stopped:
        assert len(calls) == 1
    elif backend == "dns":
        assert calls[-1] == ("exec", "-T", "dns", "rndc", "-t", "3", "status")
    else:
        assert calls[-1][-1] == "status-get"


@pytest.mark.parametrize("ndjson", [False, True])
def test_ca_only_readiness_reads_compose_status_formats(installer, tmp_path, monkeypatch, ndjson):
    """Accept supported Compose JSON formats for a CA-only deployment."""
    state = {"dns": "no", "dhcp": "none", "radius": "no", "ca": "yes"}
    records = [{"Service": name, "State": "running"} for name in ("ca-agent", "ca-runtime")]
    output = "\n".join(map(json.dumps, records)) if ndjson else json.dumps(records)
    calls = []

    def command(_directory, *args, **_kwargs):
        """Supply synthetic Compose status or reject native daemon commands."""
        calls.append(args)
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(installer, "compose", command)
    installer.check_daemons(tmp_path, state, attempts=1)
    assert calls == [("ps", "--all", "--format", "json")]


def test_printed_python_resume_command_is_accepted(
    installer, tmp_path, monkeypatch, capsys, compose_available
):
    """Execute the printed recovery command using the actual argument parser."""
    directory = tmp_path / "prepared installation"
    monkeypatch.setattr(installer, "validate", lambda _args: None)
    installer.main(
        [
            "--directory",
            str(directory),
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
            "--version",
            "0.0.0-test",
            "--source-directory",
            str(ROOT),
            "--prepare-only",
        ]
    )
    command = shlex.split(capsys.readouterr().out.splitlines()[-1])
    assert command[0] == "sudo"
    assert command[2] == str(directory / "bootstrap/install_services.py")
    resumed = []
    monkeypatch.setattr(installer, "start", resumed.append)
    installer.main(command[3:])
    assert resumed == [directory]


def test_resume_dry_run_reuses_saved_credentials_and_versions(tmp_path):
    """Describe recovery without regenerating or downloading deployment state."""
    directory = tmp_path / "existing deployment"
    directory.mkdir()
    marker = directory / "installation.json"
    marker.write_text("synthetic saved state")
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--resume",
            "--dry-run",
            "--directory",
            str(directory),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Would resume the saved deployment" in result.stdout
    assert (
        "reuse saved configuration, service selection, image versions and credentials"
        in result.stdout
    )
    assert "Would download release" not in result.stdout
    assert "Transport credentials generated" not in result.stdout
    assert marker.read_text() == "synthetic saved state"


@pytest.mark.parametrize("private_kea", [False, True])
def test_release_publication_checks_anonymous_kea_access(tmp_path, private_kea):
    """Block installer publication when a release image cannot be pulled anonymously."""
    tools = tmp_path / "tools"
    tools.mkdir()
    calls = tmp_path / "calls"
    docker = tools / "docker"
    docker.write_text("""#!/bin/sh
[ "$1" = --config ] && [ -d "$2" ] && [ -z "$(ls -A "$2")" ] || exit 2
[ "$3 $4" = "manifest inspect" ] || exit 2
printf '%s\\n' "$5" >> "$PUBLIC_CALLS"
if [ "$PRIVATE_KEA" = yes ]; then
  case "$5" in */netadmin-dhcp-kea:*) exit 1;; esac
fi
""")
    docker.chmod(0o700)
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(ROOT / "Tools/check_public_images.sh"), "0.0.0-test"],
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "PUBLIC_CALLS": str(calls),
            "PRIVATE_KEA": "yes" if private_kea else "no",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    images = calls.read_text().splitlines()
    assert "ghcr.io/timlaing/netadmin-dhcp-kea:0.0.0-test" in images
    if private_kea:
        assert result.returncode != 0
        assert "Set the GHCR package visibility to Public" in result.stderr
    else:
        assert result.returncode == 0
        assert len(images) == 10
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    assert "verify-public-images" in workflow["jobs"]["publish-installer"]["needs"]


def test_inherited_compose_selectors_cannot_change_installation(installer, tmp_path, monkeypatch):
    """Prevent inherited Compose variables from overriding saved service choices."""
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
    """Preview independent service choices without creating deployment files."""
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
    """Reject an empty selection before writing deployment state."""
    args = options(tmp_path, "no", "none", "no", "no")
    with pytest.raises(ValueError, match="at least one"):
        installer.validate(args, host=False)


def test_launcher_accepts_script_from_pipeline(tmp_path):
    """Keep terminal input separate from a script supplied on standard input."""
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
    """Preserve arguments through elevation without evaluating their shell characters."""
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
    """Publish and smoke-test Kea images for both supported architectures."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    entries = workflow["jobs"]["publish"]["strategy"]["matrix"]["include"]
    kea = [entry for entry in entries if entry["flavour"] == "dhcp-kea"]
    assert {entry["arch"] for entry in kea} == {"amd64", "aarch64"}
    for entry in kea:
        assert (ROOT / entry["smoke"]).is_file()
    assert "'-dhcp-kea'" in workflow["jobs"]["manifests"]["steps"][1]["run"]


def installer_release(tag, *, ready=True):
    """Build release metadata with controllable publication readiness."""
    names = ["install.sh", "install.sh.sha256", "compose.yml"]
    if ready:
        names.append("installer-ready.json")
    return {
        "tag_name": tag,
        "assets": [{"name": name, "state": "uploaded", "size": 10} for name in names],
    }


@pytest.mark.parametrize("incomplete", ["marker", "upload", "empty", "draft", "prerelease"])
def test_latest_installer_skips_unavailable_release(incomplete):
    """Keep the previous verified release available during incomplete publication."""
    newest = installer_release("v99.0.0", ready=incomplete != "marker")
    if incomplete == "upload":
        newest["assets"][0]["state"] = "uploading"
    elif incomplete == "empty":
        newest["assets"][0]["size"] = 0
    elif incomplete in {"draft", "prerelease"}:
        newest[incomplete] = True
    result = run_release_selector([[newest, installer_release("v1.2.3")]])
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1.2.3"


def run_release_selector(pages):
    """Execute the shipped resolver with synthetic paginated GitHub responses."""
    source = (ROOT / "scripts/install.sh").read_text().split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    harness = (
        "import io, json, urllib.request\n"
        f"pages = iter({pages!r})\n"
        "def response(request, timeout):\n"
        "    assert timeout == 30\n"
        "    assert request.full_url.startswith("
        '"https://api.github.com/repos/timlaing/net-admin/releases?per_page=100&page=")\n'
        "    return io.StringIO(json.dumps(next(pages)))\n"
        "urllib.request.urlopen = response\n"
    )
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", harness + source], capture_output=True, text=True, check=False
    )


def test_latest_installer_requires_completed_release():
    """Fail clearly before any verified installer release exists."""
    result = run_release_selector([[installer_release("v2.0.0", ready=False)]])
    assert result.returncode != 0
    assert "No verified stable NetAdmin installer release" in result.stderr


def test_latest_installer_checks_older_release_pages():
    """Find a completed release beyond the first page of incomplete releases."""
    result = run_release_selector(
        [[installer_release("v2.0.0", ready=False)] * 100, [installer_release("v1.0.0")]]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1.0.0"


def test_release_ready_marker_is_published_last():
    """Publish readiness only after verified images and installer assets."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    job = workflow["jobs"]["publish-installer"]
    assert "verify-public-images" in job["needs"]
    assert "gh release upload" in job["steps"][-1]["run"]
    assert "installer-ready.json" in job["steps"][-1]["run"]
    assert "install.sh.sha256" in job["steps"][-2]["run"]


@pytest.mark.parametrize("document", ["README.md", "docs/installation.md"])
def test_documented_install_command_stops_when_download_fails(tmp_path, document):
    """Preserve download failures without executing a partial installer."""
    command = next(
        line
        for line in (ROOT / document).read_text().splitlines()
        if line.startswith("curl ") and "&& bash install.sh" in line
    )
    tools = tmp_path / "tools"
    tools.mkdir()
    marker = tmp_path / "executed"
    (tools / "curl").write_text("#!/bin/sh\nexit 22\n")
    (tools / "bash").write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n")
    for tool in tools.iterdir():
        tool.chmod(0o700)
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", command],
        cwd=tmp_path,
        env={**os.environ, "PATH": str(tools)},
        check=False,
    )
    assert result.returncode == 22
    assert not marker.exists()


@pytest.mark.parametrize(
    "dns,radius,ca",
    [("yes", "no", "no"), ("no", "yes", "no"), ("no", "no", "yes"), ("yes", "yes", "yes")],
)
def test_macos_prepares_only_desktop_services(
    installer, tmp_path, compose_available, dns, radius, ca
):
    """Prepare independent Mac service selections without host networking or DHCP."""
    args = options(tmp_path, dns=dns, dhcp="none", radius=radius, ca=ca)
    args.platform = "macos"
    installer.validate(args, host=False)
    installer.prepare(args)
    config = yaml.safe_load((args.directory / "compose.yml").read_text())
    assert not any(name.startswith("dhcp") for name in config["services"])
    selected = {name for name in ("dns", "radius", "ca") if getattr(args, name) == "yes"}
    expected = {
        "dns": {"dns", "dns-agent"},
        "radius": {"radius", "radius-agent"},
        "ca": {"ca-runtime", "ca-agent"},
    }
    effective = {
        name
        for name, service in config["services"].items()
        if not service.get("profiles") or selected.intersection(service["profiles"])
    }
    assert effective == set().union(*(expected[name] for name in selected))
    if ca == "yes":
        assert (
            "${INSTALL_ADDRESS:?}:9100-9115:9100-9115" in config["services"]["ca-runtime"]["ports"]
        )
    assert config["services"]["dns-agent"]["network_mode"] == "service:dns"
    assert all(service.get("network_mode") != "host" for service in config["services"].values())
    assert "${INSTALL_ADDRESS:?}:53:53/udp" in config["services"]["dns"]["ports"]
    assert "AGENT_BIND_ADDRESS=0.0.0.0" in (args.directory / "agents.env").read_text()
    assert json.loads((args.directory / "installation.json").read_text())["platform"] == "macos"
    if dns == "yes":
        assert "listen-on { any; };" in (args.directory / "config/bind/named.conf").read_text()


def test_macos_rejects_dhcp_before_writes(installer, tmp_path):
    """Do not claim LAN DHCP support through Desktop port forwarding."""
    args = options(tmp_path)
    args.platform = "macos"
    with pytest.raises(ValueError, match="DHCP requires a native Linux host"):
        installer.validate(args, host=False)
    assert not args.directory.exists()


def test_macos_probes_only_published_ports(installer, tmp_path, port_probe):
    """Leave VM-only RNDC and loopback DNS ports out of Mac host preflight."""
    args = options(tmp_path, dhcp="none")
    args.platform = "macos"
    installer.check_ports(args)
    assert all(host == args.address and port >= 1024 for host, port, _ in port_probe.bindings)
    assert (args.address, 8083, socket.SOCK_STREAM) in port_probe.bindings


def test_macos_launcher_preview(tmp_path):
    """A Mac preview selects Desktop and defaults DHCP off without mutation."""
    tools = tmp_path / "tools"
    tools.mkdir()
    uname = tools / "uname"
    uname.write_text('#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n')
    uname.chmod(0o700)
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--dry-run",
            "--address",
            "192.0.2.10",
            "--directory",
            str(tmp_path / "new"),
        ],
        env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Docker Desktop" in result.stdout
    assert "DHCP=none" in result.stdout
    assert not (tmp_path / "new").exists()


def test_macos_bootstrap_reuses_desktop_without_root_or_linux_commands(tmp_path):
    """Exercise dependency selection and helper handoff with mocked host commands."""
    tools = tmp_path / "tools"
    tools.mkdir()
    calls = tmp_path / "calls"
    commands = {
        "uname": 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac',
        "docker": 'echo "docker $*" >> "$MAC_CALLS"; exit 0',
        "brew": (
            'echo "brew $*" >> "$MAC_CALLS"; if [ "$1" = --prefix ]; then echo "$MAC_TOOLS"; fi'
        ),
        "open": 'echo "open $*" >> "$MAC_CALLS"',
        "curl": (
            'echo "curl $*" >> "$MAC_CALLS"; while [ "$#" -gt 0 ]; do '
            'if [ "$1" = -o ]; then shift; : > "$1"; fi; shift; done'
        ),
        "python3": 'echo "python $*" >> "$MAC_CALLS"; echo "--platform"',
        "sudo": 'echo forbidden-sudo >> "$MAC_CALLS"; exit 99',
        "apt-get": 'echo forbidden-apt >> "$MAC_CALLS"; exit 99',
        "dnf": 'echo forbidden-dnf >> "$MAC_CALLS"; exit 99',
    }
    for name, body in commands.items():
        command = tools / name
        command.write_text("#!/bin/sh\n" + body + "\n")
        command.chmod(0o700)
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--address",
            "192.0.2.10",
            "--version",
            "1.2.3",
            "--directory",
            str(tmp_path / "deployment"),
            "--dns",
            "no",
            "--radius",
            "no",
            "--ca",
            "yes",
        ],
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "MAC_CALLS": str(calls),
            "MAC_TOOLS": str(tools),
        },
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0
    recorded = calls.read_text()
    assert "open -a Docker" in recorded
    assert "brew list --versions python@3.13" in recorded
    assert "docker compose version" in recorded
    assert "--platform macos" in recorded
    assert "--dhcp none" in recorded
    assert "forbidden" not in recorded


@pytest.mark.parametrize(
    "platform,dhcp,host,message",
    [("linux", "none", "macos", "does not match"), ("macos", "isc", "macos", "cannot enable DHCP")],
)
def test_resume_rejects_incompatible_platform_before_docker(
    installer, monkeypatch, platform, dhcp, host, message
):
    """Saved Linux or DHCP workloads cannot be resumed as macOS services."""
    monkeypatch.setattr(installer, "host_platform", lambda: host)
    monkeypatch.setattr(
        installer,
        "run",
        lambda *_a, **_k: pytest.fail("Docker contacted before platform rejection"),
    )
    state = {"platform": platform, "dhcp": dhcp}
    with pytest.raises(ValueError, match=message):
        installer.validate_resume(state)


def test_resume_rejects_remote_docker_before_any_compose(installer, monkeypatch, tmp_path):
    """A remote context must never receive saved deployments or bind mounts."""
    state = {"schema": 1, "project": installer.PROJECT, "platform": "linux", "dhcp": "none"}
    (tmp_path / "installation.json").write_text(json.dumps(state))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    calls = []

    def run(command, **_kwargs):
        """Expose only local context metadata; any other operation fails the regression."""
        calls.append(command)
        assert command == ["docker", "context", "inspect"]
        return SimpleNamespace(
            stdout=json.dumps([{"Endpoints": {"docker": {"Host": "ssh://remote"}}}])
        )

    monkeypatch.setattr(installer, "run", run)
    monkeypatch.setattr(
        installer, "compose", lambda *_a, **_k: pytest.fail("remote Compose invoked")
    )
    with pytest.raises(ValueError, match="Remote Docker contexts"):
        installer.start(tmp_path)
    assert len(calls) == 1


def test_legacy_resume_manifest_is_linux_only(installer, monkeypatch):
    """Accept an old Linux manifest while retaining the current engine preflight."""
    checked = []
    monkeypatch.setattr(installer, "validate_engine", checked.append)
    installer.validate_resume({"dhcp": "none"})
    assert checked == ["linux"]


def test_macos_printed_resume_keeps_desktop_user(
    installer, tmp_path, monkeypatch, capsys, compose_available
):
    """Do not elevate away from the user's Desktop context in recovery instructions."""
    monkeypatch.setattr(installer, "host_platform", lambda: "macos")
    monkeypatch.setattr(installer, "validate", lambda _args: None)
    installer.main(
        [
            "--directory",
            str(tmp_path / "mac"),
            "--address",
            "192.0.2.10",
            "--platform",
            "macos",
            "--dhcp",
            "none",
            "--dns",
            "no",
            "--radius",
            "no",
            "--ca",
            "yes",
            "--version",
            "1.2.3",
            "--source-directory",
            str(ROOT),
            "--prepare-only",
        ]
    )
    command = shlex.split(capsys.readouterr().out.splitlines()[-1])
    assert command[0] == sys.executable
    assert command[command.index("--platform") + 1] == "macos"
    assert "sudo" not in command


@pytest.mark.parametrize("platform,expected", [("linux", 0), ("macos", 1)])
def test_bootstrap_handoff_is_compatible_with_old_linux_helper(tmp_path, platform, expected):
    """Keep Linux installs working and clearly reject a release without Mac support."""
    temporary = tmp_path / "download"
    temporary.mkdir()
    helper = temporary / "install_services.py"
    helper.write_text(
        "import argparse\np=argparse.ArgumentParser()\n"
        'for flag in "directory address interface dns dhcp radius ca version".split():\n'
        ' p.add_argument("--" + flag)\np.parse_args()\n'
    )
    launcher = (ROOT / "scripts/install.sh").read_text()
    start = launcher.index('\nargs=(--directory "$directory"') + 1
    section = launcher[start : launcher.index("\n}\n# Parse the complete body", start)]
    prefix = (
        'set -euo pipefail\ndirectory="$1"\ntemporary="$2"\npython_command="$3"\nplatform="$4"\n'
        'address=192.0.2.10; interface=""; dns=no; dhcp=none; radius=no; ca=yes;\n'
        'version=1.2.3; prepare_only=false; pair=false; source_directory=""\n'
        'fail() { echo "$*" >&2; exit 1; }\n'
    )
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            "-c",
            prefix + section,
            "probe",
            str(tmp_path / "deployment"),
            str(temporary),
            sys.executable,
            platform,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected
    if platform == "macos":
        assert "predates macOS support" in result.stderr
    else:
        assert "unrecognized arguments" not in result.stderr


@pytest.mark.parametrize(
    "platform,saved,dhcp,endpoint,message",
    [
        ("linux", "linux", "none", "ssh://remote", "Remote Docker contexts"),
        ("macos", "linux", "none", "unix:///tmp/docker.sock", "does not match"),
        ("macos", "macos", "isc", "unix:///tmp/docker.sock", "cannot enable DHCP"),
    ],
)
def test_bootstrap_preflight_protects_saved_older_helpers(
    tmp_path, platform, saved, dhcp, endpoint, message
):
    """Old saved helpers receive the same host/endpoint guards before being executed."""
    directory = tmp_path / "deployment"
    directory.mkdir()
    (directory / "installation.json").write_text(
        json.dumps({"schema": 1, "project": "netadmin-services", "platform": saved, "dhcp": dhcp})
    )
    launcher = (ROOT / "scripts/install.sh").read_text()
    source = launcher.split("<<'PREFLIGHT'\n", 1)[1].split("\nPREFLIGHT", 1)[0]
    contexts = [{"Endpoints": {"docker": {"Host": endpoint}}}]
    harness = (
        "import sys, subprocess\nfrom types import SimpleNamespace\n"
        f"sys.argv = {['preflight', str(directory), platform, 'true']!r}\n"
        f"subprocess.run = lambda *_a, **_k: SimpleNamespace(stdout={json.dumps(contexts)!r})\n"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"DOCKER_HOST", "DOCKER_CONTEXT"}
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", harness + source],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("content", [None, "{", "[]", "null", "\xff"])
def test_bootstrap_resume_invalid_manifest_has_friendly_error(tmp_path, content):
    """Reject missing or invalid manifests before Docker without a traceback."""
    if content is not None:
        (tmp_path / "installation.json").write_bytes(content.encode("latin1"))
    launcher = (ROOT / "scripts/install.sh").read_text()
    source = launcher.split("<<'PREFLIGHT'\n", 1)[1].split("\nPREFLIGHT", 1)[0]
    harness = (
        "import sys, subprocess\n"
        f"sys.argv = {['preflight', str(tmp_path), 'macos', 'true']!r}\n"
        "def unexpected(*args, **kwargs):\n raise AssertionError('Docker contacted')\n"
        "subprocess.run = unexpected\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", harness + source],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "deployment" in result.stderr
    assert "Traceback" not in result.stderr
    assert "Docker contacted" not in result.stderr
