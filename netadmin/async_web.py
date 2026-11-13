"""Content negotiation for progressively enhanced deletion forms."""

from typing import Any

from flask import flash, jsonify, redirect, request


def wants_json() -> bool:
    """Recognize the explicit JSON acknowledgement requested by the browser."""
    return request.accept_mimetypes.best == "application/json"


def deletion_response(destination: str, message: str = "") -> Any:
    """Acknowledge a completed deletion without leaving flash messages behind."""
    if wants_json():
        response = jsonify(deleted=True, refresh_url=destination)
        response.headers["Cache-Control"] = "no-store"
        return response
    if message:
        flash(message, "success")
    return redirect(destination)
