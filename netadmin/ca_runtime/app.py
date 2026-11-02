"""Authenticated Unix-socket API for CA-local lifecycle operations."""

from __future__ import annotations

import hmac
import os
import signal
import subprocess  # nosec B404
import threading
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from netadmin.ca_runtime import issuer
from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.store import AuthorityStore, identifier
from netadmin.services.radius_certificates import certificate_info


def create_runtime(root: Path, token: str) -> Flask:
    """Create a controller; signing keys and subprocesses stay within this runtime."""
    if len(token) < 32:
        raise CAInputError("A separate management token of at least 32 characters is required")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 131072
    store = AuthorityStore(root)
    app.extensions["ca_store"] = store
    app.extensions["ca_issuers"] = issuer.Issuers(store)

    @app.before_request
    def authenticate() -> Any:
        if not hmac.compare_digest(request.headers.get("X-CA-Management-Token", ""), token):
            return jsonify({"error": "Management authentication required"}), 403
        return None

    @app.after_request
    def no_cache(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(CAInputError)
    def input_error(error: CAInputError) -> Any:
        return jsonify({"error": str(error), "outcome": "rejected"}), 400

    @app.errorhandler(ValueError)
    @app.errorhandler(OSError)
    @app.errorhandler(KeyError)
    @app.errorhandler(subprocess.SubprocessError)
    @app.errorhandler(httpx.HTTPError)
    def operation_error(_error: Exception) -> Any:
        # Never echo subprocess, decryption, filesystem or submitted secret values.
        return jsonify(
            {
                "error": "Operation rejected or incomplete. "
                "Refresh authority state and operation status before retrying."
            }
        ), 409

    @app.get("/authorities")
    def authorities() -> Any:
        state = store.status()
        processes = app.extensions["ca_issuers"].processes
        for authority in state["authorities"]:
            process = processes.get(authority["id"])
            authority["running"] = bool(process and process.poll() is None)
        return jsonify(state)

    @app.get("/operations/<operation_id>")
    def operation_status(operation_id: str) -> Any:
        import json  # pylint: disable=import-outside-toplevel

        record = root / "operations" / (identifier(operation_id) + ".json")
        if not record.exists():
            return jsonify({"state": "not_found"}), 404
        result = json.loads(record.read_text())
        return jsonify({"state": result["state"], "result": result.get("result")})

    @app.post("/authorities/<action>")
    def mutate(action: str) -> Any:
        body = request.get_json()
        if not isinstance(body, dict):
            return jsonify({"error": "Expected JSON object"}), 400
        if action == "export-root":
            with store.lock():
                return jsonify(store.export_root(body))
        actions = {
            "root": store.create_root,
            "subordinate": subordinate,
            "archive-root": store.archive_root,
        }
        if action not in actions:
            return jsonify({"error": "Unknown operation"}), 404
        return jsonify(store.operation({**body, "action": action}, lambda: actions[action](body)))

    def subordinate(body: dict[str, Any]) -> dict[str, Any]:
        # Validate policy, endpoint and capacity before generating any certificate.
        limits = None
        parent_id = str(body.get("parent_id", ""))
        if not body.get("csr") or body.get("dns_suffixes") or body.get("ip_ranges"):
            limits = issuer.policy(body)
            issuer.check_parent_policy(store, parent_id, limits)
        elif store.metadata(parent_id).get("policy"):
            raise CAInputError("External child requires explicit inherited issuance scope")
        if not body.get("csr"):
            issuer.service_host(body)
            if len(list((store.root / "authorities").glob("*/config.json"))) >= 16:
                raise CAInputError("At most 16 managed issuers are supported")
        result = store.create_subordinate({**body, "effective_policy": limits})
        if not body.get("csr"):
            issuer.configure(store, result["id"], body)
        return result

    @app.post("/authorities/<authority_id>/issue")
    def issue(authority_id: str) -> Any:
        body = request.get_json()
        if not isinstance(body, dict):
            return jsonify({"error": "Expected JSON object"}), 400
        identifier(authority_id)
        payload = {**body, "issuer_id": authority_id}
        return jsonify(store.operation(payload, lambda: issuer.sign(store, authority_id, payload)))

    @app.post("/authorities/<authority_id>/revoke")
    def revoke(authority_id: str) -> Any:
        body = request.get_json()
        if not isinstance(body, dict):
            return jsonify({"error": "Expected JSON object"}), 400
        identifier(authority_id)
        payload = {**body, "issuer_id": authority_id, "action": "revoke"}
        return jsonify(
            store.operation(payload, lambda: issuer.revocation(store, authority_id, payload))
        )

    @app.get("/authorities/<authority_id>/crl")
    def download_crl(authority_id: str) -> Any:
        return jsonify({"pem": issuer.crl(store, authority_id).public_bytes(Encoding.PEM).decode()})

    @app.get("/authorities/<authority_id>/certificates")
    def certificates(authority_id: str) -> Any:
        directory = store.directory(authority_id)
        certificates = []
        for path in sorted(directory.glob("*.pem")):
            if len(path.stem) == 32:
                cert = x509.load_pem_x509_certificate(path.read_bytes())
                certificates.append({**certificate_info(cert), "pem": path.read_text()})
        return jsonify({"certificates": certificates})

    @app.get("/authorities/<authority_id>/chain")
    def chain(authority_id: str) -> Any:
        return jsonify({"pem": store.chain(authority_id).decode()})

    return app


def main() -> None:
    """Serve the private controller and supervise issuing services until shutdown."""
    token = Path(os.environ["CA_MANAGEMENT_TOKEN_FILE"]).read_text(encoding="utf-8").strip()
    app = create_runtime(Path(os.getenv("CA_RUNTIME_DIR", "/state")), token)
    socket_path = os.getenv("CA_CONTROL_SOCKET", "/control/ca.sock")
    Path(socket_path).unlink(missing_ok=True)
    server = make_server("unix://" + socket_path, 0, app)
    os.chmod(socket_path, 0o660)
    stop = threading.Event()

    def shutdown(_signum: int, _frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    processes = app.extensions["ca_issuers"]
    try:
        while not stop.wait(1):
            with app.extensions["ca_store"].lock():
                try:
                    processes.reconcile()
                except OSError:
                    app.logger.error(
                        "Issuer startup failed; inspect runtime storage and executable permissions"
                    )
    finally:
        server.shutdown()
        processes.close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
