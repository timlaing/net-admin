"""Narrow gateway to the CA-local controller; never mounts authority signing keys."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

import httpx
from flask import Flask, Response, jsonify, request


def register_lifecycle(app: Flask) -> None:
    """Opt into lifecycle routes only when a controller socket is configured."""
    socket_path = os.getenv("CA_CONTROL_SOCKET", "")
    if not socket_path:
        return
    token = Path(os.environ["CA_MANAGEMENT_TOKEN_FILE"]).read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ValueError("CA lifecycle management token is too short")

    def proxy(path: str) -> Any:
        # A RADIUS/leaf credential alone must never authorize root or CA creation.
        if not hmac.compare_digest(request.headers.get("X-CA-Management-Token", ""), token):
            return jsonify({"error": "Separate CA management credential required"}), 403
        try:
            transport = httpx.HTTPTransport(uds=socket_path)
            with httpx.Client(transport=transport) as client:
                response = client.request(
                    request.method,
                    "http://controller/" + path,
                    headers={"X-CA-Management-Token": token},
                    json=request.get_json(silent=True) if request.method == "POST" else None,
                    timeout=90,
                )
            return Response(
                response.content,
                status=response.status_code,
                headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
            )
        except httpx.HTTPError:
            return jsonify(
                {"error": "CA controller unavailable; inspect operation status before retrying"}
            ), 502

    app.add_url_rule("/authorities", "authorities", lambda: proxy("authorities"))
    app.add_url_rule(
        "/authorities/<action>",
        "authority_action",
        lambda action: proxy("authorities/" + action),
        methods=["POST"],
    )
    app.add_url_rule(
        "/authorities/<authority_id>/<action>",
        "authority_detail",
        lambda authority_id, action: proxy("authorities/" + authority_id + "/" + action),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/operations/<operation_id>",
        "authority_operation",
        lambda operation_id: proxy("operations/" + operation_id),
    )
