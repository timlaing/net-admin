"""On-demand administrator publication status; no registry or release mutations."""

import re
from typing import Any

import httpx
from flask import Blueprint, jsonify

from netadmin.auth import admin_required
from netadmin.release_metadata import REPO, publication_state

release_web = Blueprint("release_status", __name__)


@release_web.get("/releases/status")
@admin_required
def status() -> Any:
    """Display uploaded completion state without presenting partial publication as ready."""
    try:
        with httpx.Client(timeout=3) as client:
            response = client.get(f"https://api.github.com/repos/{REPO}/releases/latest")
            response.raise_for_status()
            release = response.json()
        tag = release.get("tag_name", "")
        tag = (
            tag
            if isinstance(tag, str) and re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", tag)
            else "unknown"
        )
        return jsonify(
            {
                "state": publication_state(release),
                "tag": tag,
                "url": f"https://github.com/{REPO}/releases",
            }
        )
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return jsonify({"state": "unknown", "error": "Could not verify release publication"}), 503
