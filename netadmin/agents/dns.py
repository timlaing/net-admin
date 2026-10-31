"""Restricted Bind agent: canonical configuration discovery and managed zones."""

from __future__ import annotations

import re
import subprocess  # nosec B404 - fixed daemon tools, no shell
from pathlib import Path
from typing import Any, cast

from flask import Flask, current_app, jsonify

from netadmin.agents.common import configured_path, create_agent, json_object, validated_transaction
from netadmin.services.dns import discover_zones


def _canonical() -> str:
    """Expand includes through Bind itself; never log configuration or keys."""
    result = subprocess.run(  # noqa: S603
        ["/usr/sbin/named-checkconf", "-p", str(current_app.config["DNS_MAIN"])],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout


def _zone_blocks(text: str) -> list[tuple[str, int, int]]:
    """Locate complete top-level zone blocks, ignoring quoted braces."""
    if re.search(r"(?m)^\s*view\s", text):
        raise ValueError("Bind views require explicit migration before management")
    result = []
    for match in re.finditer(r'(?m)^\s*zone\s+"([^"]+)"[^\n{]*\{', text):
        depth = 1
        quoted = False
        escaped = False
        index = match.end()
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
        end = text.index(";", index) + 1
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
            ["/usr/sbin/named-checkconf", "-z", str(main)],
            check=True,
            capture_output=True,
            timeout=20,
        )

    validated_transaction(changes, validate, ["/usr/sbin/rndc", "reconfig"])


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
    path = directory / (name + ".zone")
    if path.exists() or path.with_suffix(path.suffix + ".jnl").exists():
        return jsonify({"error": "Existing zone data must be imported explicitly"}), 409
    content = str(body.get("content", ""))
    if not content or len(content) > 1_000_000:
        raise ValueError("Provide a complete zone file of at most 1 MB")
    declaration = f'\nzone "{name}" {{ type primary; file "{path}"; }};\n'
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
    app = create_agent(__name__)
    app.config.update(
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

    app.add_url_rule("/zones", view_func=_zones, methods=["GET"])
    app.add_url_rule("/zones", view_func=_create, methods=["POST"])
    app.add_url_rule("/zones/delete", view_func=_delete, methods=["POST"])
    return app
