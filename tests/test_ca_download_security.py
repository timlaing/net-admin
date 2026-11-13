"""Legacy CA downloads cannot traverse records or follow filesystem links."""

import errno
import os
from pathlib import Path

import pytest

from netadmin.agents.ca import MAX_CERTIFICATE_BYTES, create_ca_agent
from netadmin.services.radius_certificates import PEM
from tests.test_radius_certificates import material as material

AUTH = {"Authorization": "Bearer synthetic"}
IDENTIFIER = "a" * 32


@pytest.fixture
def downloads(tmp_path, monkeypatch, material):
    ledger = tmp_path / "ledger"
    monkeypatch.setenv("NETADMIN_AGENT_TOKEN", "synthetic")
    monkeypatch.setenv("CA_DATA_DIR", str(ledger))
    monkeypatch.setenv("STEP_CA_ROOT", str(material[0] / "ca.pem"))
    app = create_ca_agent()
    app.config["TESTING"] = True
    return app.test_client(), ledger, material[1].public_bytes(PEM)


@pytest.mark.parametrize(
    "identifier",
    [
        "invalid",
        "..",
        "a" * 31,
        "A" * 32,
        "a" * 33,
        "a" * 32 + ".",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ],
)
def test_invalid_ids_never_reach_record_filesystem(downloads, monkeypatch, identifier):
    client, _ledger, _pem = downloads

    def unexpected_read(_record_id):
        pytest.fail("Invalid IDs must be rejected before accessing a record")

    monkeypatch.setattr("netadmin.agents.ca._record_certificate", unexpected_read)
    response = client.get(f"/certificates/{identifier}", headers=AUTH)
    assert response.status_code == 404
    assert response.json == {"error": "Unknown certificate"}


def test_public_certificate_and_configured_root_remain_downloadable(downloads):
    client, ledger, pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    (record / "certificate.pem").write_bytes(pem)
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 200
    assert response.json == {"pem": pem.decode("ascii")}
    assert client.get("/certificates/root", headers=AUTH).status_code == 200
    assert client.get(f"/certificates/{IDENTIFIER}").status_code == 401


@pytest.mark.parametrize("link", ["record", "certificate"])
def test_symlinked_records_and_certificates_cannot_expose_external_files(downloads, link):
    client, ledger, pem = downloads
    external = ledger.parent / "external"
    external.mkdir()
    (external / "certificate.pem").write_bytes(pem)
    record = ledger / IDENTIFIER
    if link == "record":
        record.symlink_to(external, target_is_directory=True)
    else:
        record.mkdir()
        (record / "certificate.pem").symlink_to(external / "certificate.pem")
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 404
    assert response.json == {"error": "Unknown certificate"}
    assert pem.decode("ascii") not in response.text


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "oversized"])
def test_unsafe_and_missing_records_have_identical_lookup_errors(downloads, kind):
    client, ledger, _pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    certificate = record / "certificate.pem"
    if kind == "directory":
        certificate.mkdir()
    elif kind == "fifo":
        os.mkfifo(certificate)
    elif kind == "oversized":
        certificate.write_bytes(b"x" * (MAX_CERTIFICATE_BYTES + 1))
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 404
    assert response.json == {"error": "Unknown certificate"}


@pytest.mark.parametrize("kind", ["success", "directory", "wrapper-failure"])
def test_all_descriptors_close_even_when_certificate_wrapper_fails(downloads, monkeypatch, kind):
    client, ledger, pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    certificate = record / "certificate.pem"
    if kind == "directory":
        certificate.mkdir()
    else:
        certificate.write_bytes(pem)
    opened = []
    closed = []
    original_open = os.open
    original_close = os.close

    def track_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def track_close(descriptor):
        closed.append(descriptor)
        original_close(descriptor)

    def failed_wrapper(_descriptor, _mode, **_kwargs):
        raise OSError("synthetic wrapper failure before taking descriptor ownership")

    monkeypatch.setattr("netadmin.agents.ca.os.open", track_open)
    monkeypatch.setattr("netadmin.agents.ca.os.close", track_close)
    if kind == "wrapper-failure":
        monkeypatch.setattr("netadmin.agents.ca.os.fdopen", failed_wrapper)
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == (200 if kind == "success" else 404)
    assert len(opened) == 3
    assert closed == opened[::-1]
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def test_inaccessible_record_does_not_expose_filesystem_details(downloads, monkeypatch):
    client, _ledger, _pem = downloads

    def inaccessible(_record_id):
        raise PermissionError("synthetic-private-path")

    monkeypatch.setattr("netadmin.agents.ca._record_certificate", inaccessible)
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 404
    assert response.json == {"error": "Unknown certificate"}
    assert "synthetic-private-path" not in response.text


def test_malformed_public_certificate_is_controlled(downloads):
    client, ledger, _pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    (record / "certificate.pem").write_text("not a certificate")
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 502
    assert response.json == {"error": "Certificate record unavailable"}


def test_record_directory_swap_cannot_redirect_open_certificate(downloads, monkeypatch):
    client, ledger, pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    (record / "certificate.pem").write_bytes(pem)
    external = ledger.parent / "external"
    external.mkdir()
    (external / "certificate.pem").write_text("outside the ledger")
    original_open = os.open

    def swap_after_directory_open(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == IDENTIFIER:
            record.rename(ledger / "retained-record")
            record.symlink_to(external, target_is_directory=True)
        return descriptor

    monkeypatch.setattr("netadmin.agents.ca.os.open", swap_after_directory_open)
    response = client.get(f"/certificates/{IDENTIFIER}", headers=AUTH)
    assert response.status_code == 200
    assert response.json == {"pem": pem.decode("ascii")}


def test_download_does_not_probe_file_existence(downloads, monkeypatch):
    client, ledger, pem = downloads
    record = ledger / IDENTIFIER
    record.mkdir()
    (record / "certificate.pem").write_bytes(pem)

    def unexpected_probe(_path):
        pytest.fail("Downloads must use pinned file descriptors, not existence probes")

    monkeypatch.setattr(Path, "is_file", unexpected_probe)
    assert client.get(f"/certificates/{IDENTIFIER}", headers=AUTH).status_code == 200
