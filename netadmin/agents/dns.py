"""Restricted Bind agent: canonical configuration discovery and managed zones."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - fixed daemon tools, no shell
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.zone
from flask import Flask, current_app, jsonify, request  # pylint: disable=wrong-import-order

from netadmin.agents.common import configured_path, create_agent, json_object, validated_transaction
from netadmin.services.dns import BindService, discover_zones


def _record_backend(zone: str) -> BindService:
    """Use only authoritative zones and the agent's locally declared update key."""
    canonical = _canonical()
    _zone_blocks(canonical)
    if zone.lower().rstrip(".") not in {item.name.lower() for item in discover_zones(canonical)}:
        raise ValueError("Unknown authoritative zone")
    key = str(current_app.config["DNS_UPDATE_KEY"])
    declaration = re.search(r'\bkey\s+"' + re.escape(key) + r'"\s*\{([^}]+)\}', canonical)
    if declaration is None:
        raise ValueError("Declare the agent's TSIG update key in Bind configuration")
    algorithm = re.search(r'\balgorithm\s+"?([\w.-]+)"?\s*;', declaration[1])
    secret = re.search(r'\bsecret\s+"([A-Za-z0-9+/=]+)"\s*;', declaration[1])
    if algorithm is None or secret is None:
        raise ValueError("Bind update key requires an algorithm and base64 secret")
    return BindService(
        str(current_app.config["DNS_SERVER"]),
        key,
        secret[1],
        algorithm[1],
        port=int(current_app.config["DNS_PORT"]),
    )


def _records() -> Any:
    zone = request.args.get("zone", "")
    if request.args.get("source") == "file":
        return _file_records(zone)
    try:
        return jsonify([asdict(item) for item in _record_backend(zone).records(zone)])
    except dns.query.TransferError:
        return jsonify({"error": "zone_transfer_refused"}), 502


def _file_records(zone: str) -> Any:
    """Read a configured zone and its journal without changing Bind or its policy."""
    canonical = _canonical()
    _zone_blocks(canonical)
    selected = next((item for item in discover_zones(canonical) if item.name == zone), None)
    if selected is None or not selected.file:
        raise ValueError("Unknown authoritative zone or missing zone file")
    directory = re.search(r'\bdirectory\s+"([^"]+)"\s*;', canonical)
    filename = Path(selected.file)
    if not filename.is_absolute():
        if directory is None:
            raise ValueError("Relative zone file requires an explicit Bind directory")
        filename = Path(directory[1]) / filename
    result = subprocess.run(  # noqa: S603 - configured Bind file, fixed executable, no shell.
        ["/usr/bin/named-compilezone", "-j", "-q", "-D", "-o", "-", zone, str(filename)],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=directory[1] if directory else filename.parent,
    )
    snapshot = dns.zone.from_text(result.stdout, origin=zone, relativize=True)
    return jsonify(
        [
            {
                "name": name.to_text(),
                "ttl": dataset.ttl,
                "record_type": dataset.rdtype.name,
                "value": record.to_text(),
            }
            for name, node in snapshot.nodes.items()
            for dataset in node.rdatasets
            for record in dataset
        ]
    )


def _record_change(delete: bool = False) -> Any:
    body = json_object()
    zone = str(body.get("zone", ""))
    backend = _record_backend(zone)
    name = str(body.get("name", ""))
    try:
        origin = dns.name.from_text(zone)
        owner = dns.name.from_text(name, origin=origin)
        kind = dns.rdatatype.from_text(str(body.get("record_type", "")).upper())
    except dns.exception.DNSException as error:
        raise ValueError("Invalid record name or type") from error
    if not name or not owner.is_subdomain(origin):
        raise ValueError("Record name must belong to the selected zone")
    record_type = kind.name
    if kind in {
        dns.rdatatype.SOA,
        dns.rdatatype.NS,
        dns.rdatatype.ANY,
        dns.rdatatype.AXFR,
        dns.rdatatype.IXFR,
        dns.rdatatype.OPT,
        dns.rdatatype.TSIG,
    }:
        raise ValueError("Protected record type")
    value = str(body.get("value", ""))
    if delete:
        backend.delete(zone, name, record_type, value)
        return jsonify({"deleted": name})
    ttl = body.get("ttl", 300)
    if (
        isinstance(ttl, bool)
        or not isinstance(ttl, int)
        or not 1 <= ttl <= 2_147_483_647
        or not value
    ):
        raise ValueError("Record requires a positive TTL and value")
    backend.upsert(zone, name, record_type, ttl, value)
    return jsonify({"saved": name})


def _delete_record() -> Any:
    return _record_change(delete=True)


def _canonical() -> str:
    """Expand includes through Bind itself; never log configuration or keys."""
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/named-checkconf", "-p", str(current_app.config["DNS_MAIN"])],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout


def _zone_end(text: str, index: int) -> int:
    """Find the closing delimiter after an opening zone brace."""
    depth = 1
    quoted = False
    escaped = False
    while index < len(text) and depth:
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            depth += (char == "{") - (char == "}")
        index += 1
    if depth or not text[index:].lstrip().startswith(";"):
        raise ValueError("Incomplete zone declaration")
    return text.index(";", index) + 1


def _zone_blocks(text: str) -> list[tuple[str, int, int]]:
    """Locate complete top-level zone blocks, ignoring quoted braces."""
    if re.search(r"(?m)^\s*view\s", text):
        raise ValueError("Bind views require explicit migration before management")
    result = []
    for match in re.finditer(r'(?m)^\s*zone\s+"([^"]+)"[^\n{]*\{', text):
        end = _zone_end(text, match.end())
        result.append((match.group(1).rstrip("."), match.start(), end))
    names = [name for name, _, _ in result]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate zone names cannot be managed")
    return result


def _install(canonical: str, extra: dict[Path, str] | None = None) -> None:
    """Migrate expanded configuration atomically, with a durable original copy."""
    main = cast(Path, current_app.config["DNS_MAIN"])
    managed = cast(Path, current_app.config["DNS_MANAGED"])
    backup = main.with_name(main.name + ".before-netadmin")
    changes = {managed: canonical, main: f'include "{managed}";\n'}
    if not backup.exists():
        changes[backup] = main.read_text(encoding="utf-8")
    changes.update(extra or {})

    def validate() -> None:
        subprocess.run(  # noqa: S603
            ["/usr/bin/named-checkconf", "-z", str(main)],
            check=True,
            capture_output=True,
            timeout=20,
        )

    validated_transaction(
        changes,
        validate,
        ["/usr/sbin/rndc", "reconfig"],
        allowed_roots=(main.parent, managed.parent, cast(Path, current_app.config["DNS_ZONE_DIR"])),
    )


def _zones() -> Any:
    canonical = _canonical()
    _zone_blocks(canonical)
    return jsonify(
        [
            {"name": zone.name, "file": zone.file, "dynamic": zone.dynamic}
            for zone in discover_zones(canonical)
        ]
    )


def _create() -> Any:
    body = json_object()
    name = str(body.get("name", "")).rstrip(".").lower()
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name):
        raise ValueError("Invalid zone name")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in name.split(".")
    ):
        raise ValueError("Invalid zone label")
    canonical = _canonical()
    if name in {zone.lower() for zone, _, _ in _zone_blocks(canonical)}:
        return jsonify({"error": "Zone already exists"}), 409
    directory = cast(Path, current_app.config["DNS_ZONE_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + ".zone")
    if path.exists() or path.with_suffix(path.suffix + ".jnl").exists():
        return jsonify({"error": "Existing zone data must be imported explicitly"}), 409
    content = str(body.get("content", ""))
    if not content or len(content) > 1_000_000:
        raise ValueError("Provide a complete zone file of at most 1 MB")
    update_key = str(current_app.config["DNS_UPDATE_KEY"])
    if not re.search(r'(?m)^\s*key\s+"' + re.escape(update_key) + r'"\s*\{', canonical):
        raise ValueError("Declare the matching TSIG update key in Bind configuration first")
    declaration = (
        f'\nzone "{name}" {{ type primary; file "{path}"; '
        f'allow-update {{ key "{update_key}"; }}; '
        f'allow-transfer {{ key "{update_key}"; }}; }};\n'
    )
    _install(canonical + declaration, {path: content})
    return jsonify({"created": name}), 201


def _delete() -> Any:
    name = str(json_object().get("name", "")).rstrip(".")
    canonical = _canonical()
    blocks = [block for block in _zone_blocks(canonical) if block[0] == name]
    if not blocks:
        return jsonify({"error": "Unknown zone"}), 404
    _, start, end = blocks[0]
    _install(canonical[:start] + canonical[end:])
    # Preserve the original zone file and journal for recovery.
    return jsonify({"deleted": name, "zone_data_preserved": True})


def create_dns_agent() -> Flask:
    """Create the bearer-protected agent; production transport requires mTLS."""
    update_key = os.getenv("DNS_UPDATE_KEY", os.getenv("NETADMIN_DNS_TSIG_NAME", "rndc-key"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", update_key):
        raise ValueError("Invalid DNS_UPDATE_KEY")
    app = create_agent(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=1_048_576,
        DNS_SERVER=os.getenv("DNS_SERVER", "127.0.0.1"),
        DNS_PORT=int(os.getenv("DNS_PORT", "53")),
        DNS_UPDATE_KEY=update_key,
        DNS_MAIN=configured_path("DNS_MAIN_CONFIG", "/etc/bind/named.conf"),
        DNS_MANAGED=configured_path("DNS_MANAGED_CONFIG", "/etc/bind/netadmin.conf"),
        DNS_ZONE_DIR=configured_path("DNS_ZONE_DIR", "/etc/bind/zones"),
    )

    @app.errorhandler(ValueError)
    def invalid(error: ValueError) -> Any:
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(subprocess.CalledProcessError)
    def rejected(_error: subprocess.CalledProcessError) -> Any:
        return jsonify({"error": "Bind rejected the operation; configuration was rolled back"}), 502

    @app.errorhandler(dns.exception.DNSException)
    @app.errorhandler(RuntimeError)
    @app.errorhandler(OSError)
    def dns_failed(_error: Exception) -> Any:
        return jsonify(
            {"error": "Bind record operation failed; check agent and Bind configuration"}
        ), 502

    app.add_url_rule("/zones", view_func=_zones, methods=["GET"])
    app.add_url_rule("/zones", view_func=_create, methods=["POST"])
    app.add_url_rule("/zones/delete", view_func=_delete, methods=["POST"])
    app.add_url_rule("/records", view_func=_records, methods=["GET"])
    app.add_url_rule("/records", view_func=_record_change, methods=["POST"])
    app.add_url_rule("/records/delete", view_func=_delete_record, methods=["POST"])
    return app
