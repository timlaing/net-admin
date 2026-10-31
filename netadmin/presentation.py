"""Shared display formatting for the application and first-run interface."""

from datetime import UTC, datetime


def display_time(value: float) -> str:
    """Format recorded timestamps consistently, with UTC labelled in the UI."""
    return datetime.fromtimestamp(value, UTC).strftime("%d %b %Y, %H:%M")
