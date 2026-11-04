"""Authenticated Unix-socket API for CA-local lifecycle operations."""

from __future__ import annotations

import hmac
import os
import shutil
import signal
import subprocess  # nosec B404
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Blueprint, Flask, current_app, jsonify, request
from werkzeug.serving import make_server

from netadmin.ca_runtime import issuer
from netadmin.ca_runtime.certificates import CAInputError
from netadmin.ca_runtime.store import AuthorityStore, identifier
from netadmin.services.radius_certificates import certificate_info

controller = Blueprint("ca_controller", __name__)


def _store() -> AuthorityStore:
    return cast(AuthorityStore, current_app.extensions["ca_store"])


def _body() -> dict[str, Any]:
    body = request.get_json()
    if not isinstance(body, dict):
        raise CAInputError("Expected JSON object")
    return cast(dict[str, Any], body)


@controller.before_request
def authenticate() -> Any:
    """Require the independent lifecycle scope on every controller request."""
    token = current_app.config["CA_MANAGEMENT_TOKEN"]
    if not hmac.compare_digest(request.headers.get("X-CA-Management-Token", ""), token):
        return jsonify({"error": "Management authentication required"}), 403
    return None


@controller.after_request
def no_cache(response: Any) -> Any:
    """Prevent caching of status and encrypted recovery responses."""
    response.headers["Cache-Control"] = "no-store"
    return response


@controller.errorhandler(CAInputError)
def input_error(error: CAInputError) -> Any:
    """Return only bounded validation messages."""
    return jsonify({"error": str(error), "outcome": "rejected"}), 400


@controller.errorhandler(ValueError)
@controller.errorhandler(OSError)
@controller.errorhandler(KeyError)
@controller.errorhandler(subprocess.SubprocessError)
@controller.errorhandler(httpx.HTTPError)
def operation_error(_error: Exception) -> Any:
    """Hide private diagnostics and preserve uncertain operation outcomes."""
    return jsonify(
        {
            "error": "Operation rejected or incomplete. "
            "Refresh authority state and operation status before retrying."
        }
    ), 409


@controller.get("/authorities")
def authorities() -> Any:
    """Return public identities and child process status."""
    state = _store().status()
    processes = current_app.extensions["ca_issuers"].processes
    for authority in state["authorities"]:
        process = processes.get(authority["id"])
        authority["running"] = bool(process and process.poll() is None)
    return jsonify(state)


@controller.get("/operations/<operation_id>")
def operation_status(operation_id: str) -> Any:
    """Read durable status without replaying a mutation."""
    import json  # pylint: disable=import-outside-toplevel

    record = _store().root / "operations" / (identifier(operation_id) + ".json")
    if not record.exists():
        return jsonify({"state": "not_found"}), 404
    result = json.loads(record.read_text())
    return jsonify({"state": result["state"], "result": result.get("result")})


def _known_parent(store: AuthorityStore, value: str) -> str:
    parent_id = identifier(value)
    directory = store.directory(parent_id)
    if store.deletion_pending(parent_id):
        raise CAInputError("Parent authority is pending deletion")
    if not all((directory / name).is_file() for name in ("metadata.json", "ca.crt")):
        raise CAInputError("Unknown parent authority")
    return parent_id


def _subordinate(store: AuthorityStore, body: dict[str, Any]) -> dict[str, Any]:
    limits = None
    parent_id = _known_parent(store, str(body.get("parent_id", "")))
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
        try:
            issuer.configure(store, result["id"], body)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            shutil.rmtree(store.directory(result["id"]))
            raise CAInputError(
                "Issuer preparation failed; authority rolled back. Use a new request ID."
            ) from error
    return result


def _delete_authority(store: AuthorityStore, body: dict[str, Any]) -> dict[str, Any]:
    """Stop an issuing process before removing its private state under the store lock."""
    authority_id = identifier(str(body.get("authority_id", "")))
    if body.get("confirmation") != "DELETE CA":
        raise CAInputError("Type DELETE CA to confirm")
    if not store.deletion_pending(authority_id) and store.has_children(authority_id):
        raise CAInputError("Delete child authorities first")
    processes = current_app.extensions["ca_issuers"].processes
    process = processes.get(authority_id)
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    processes.pop(authority_id, None)
    return store.delete_authority(body)


@controller.post("/authorities/<action>")
def mutate(action: str) -> Any:
    """Dispatch an allowlisted lifecycle operation under its stable identity."""
    body = _body()
    store = _store()
    if action == "export-root":
        with store.lock():
            return jsonify(store.export_root(body))
    actions: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "root": store.create_root,
        "subordinate": lambda payload: _subordinate(store, payload),
        "archive-root": store.archive_root,
        "delete": lambda payload: _delete_authority(store, payload),
    }
    if action not in actions:
        return jsonify({"error": "Unknown operation"}), 404
    return jsonify(store.operation({**body, "action": action}, lambda: actions[action](body)))


@controller.post("/authorities/<authority_id>/issue")
def issue(authority_id: str) -> Any:
    """Issue a leaf using the explicitly selected native issuer."""
    body = _body()
    identifier(authority_id)
    payload = {**body, "issuer_id": authority_id, "action": "issue"}
    store = _store()
    return jsonify(store.operation(payload, lambda: issuer.sign(store, authority_id, payload)))


@controller.post("/authorities/<authority_id>/revoke")
def revoke(authority_id: str) -> Any:
    """Reconcile issuer-specific revocation under the original operation ID."""
    body = _body()
    identifier(authority_id)
    payload = {**body, "issuer_id": authority_id, "action": "revoke"}
    store = _store()
    return jsonify(
        store.operation(payload, lambda: issuer.revocation(store, authority_id, payload))
    )


@controller.get("/authorities/<authority_id>/crl")
def download_crl(authority_id: str) -> Any:
    """Return the selected issuer's authoritative signed CRL."""
    return jsonify({"pem": issuer.crl(_store(), authority_id).public_bytes(Encoding.PEM).decode()})


@controller.get("/authorities/<authority_id>/certificates")
def certificates(authority_id: str) -> Any:
    """List public leaf certificates recorded by this issuer."""
    after = request.args.get("after", "")
    if after:
        identifier(after)
    store = _store()
    pems, next_cursor = store.inventory.page(store.directory(authority_id), after)
    result = [
        {**certificate_info(x509.load_pem_x509_certificate(pem.encode())), "pem": pem}
        for pem in pems
    ]
    return jsonify(
        {
            "certificates": result,
            "next_cursor": next_cursor,
            "import_pending": store.inventory.pending(store.directory(authority_id)),
        }
    )


@controller.get("/authorities/<authority_id>/chain")
def chain(authority_id: str) -> Any:
    """Return the selected public authority chain."""
    return jsonify({"pem": _store().chain(authority_id).decode()})


def create_runtime(root: Path, token: str) -> Flask:
    """Create a private, non-cookie API; UI CSRF remains enforced in the web app."""
    if len(token) < 32:
        raise CAInputError("A separate management token of at least 32 characters is required")
    # This API accepts only a scoped bearer credential over a private Unix socket.
    # It has no browser sessions/cookies; the browser-facing app enforces CSRF.
    app = Flask(__name__)  # NOSONAR
    app.config.update(MAX_CONTENT_LENGTH=131072, CA_MANAGEMENT_TOKEN=token)
    store = AuthorityStore(root)
    app.extensions["ca_store"] = store
    app.extensions["ca_issuers"] = issuer.Issuers(store)
    app.register_blueprint(controller)
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
        app.extensions["ca_store"].inventory.close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
