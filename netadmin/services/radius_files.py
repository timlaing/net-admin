"""Loss-minimizing parsers and transforms for FreeRADIUS files backends."""

from __future__ import annotations

import re
from dataclasses import dataclass

from netadmin.services.radius_users import (
    RadiusUser,
    migrate_authorize,
    migrate_to_managed,
    parse_authorize,
)

__all__ = [
    "RadiusClient",
    "RadiusUser",
    "edit_client",
    "migrate_authorize",
    "migrate_to_managed",
    "parse_authorize",
    "parse_clients",
    "render_clients",
]

CLIENT = re.compile(r"(?ms)^client\s+([A-Za-z0-9_.-]+)\s*\{(.*?)^\}")


@dataclass(frozen=True, slots=True)
class RadiusClient:
    """Safe view of a RADIUS client; secrets are intentionally absent."""

    name: str
    address: str
    shortname: str


def parse_clients(text: str) -> list[RadiusClient]:
    """Parse clients without exposing shared secrets."""
    result = []
    for name, body in CLIENT.findall(text):
        address = re.search(r"(?m)^\s*ipaddr\s*=\s*([^\s#]+)", body)
        shortname = re.search(r'(?m)^\s*shortname\s*=\s*("(?:\\.|[^"\\])*"|[^\s#]+)', body)
        if address:
            result.append(
                RadiusClient(
                    name,
                    address.group(1).strip('"'),
                    shortname.group(1).strip('"') if shortname else "",
                )
            )
    return result


def render_clients(clients: dict[str, tuple[str, str, str]]) -> str:
    """Render a dedicated managed clients include."""
    lines = ["# Managed by NetAdmin. Secrets are never returned by the API."]
    for name, (address, shortname, secret) in sorted(clients.items()):
        lines.extend(
            [
                f"client {name} {{",
                f"  ipaddr = {address}",
                f'  shortname = "{shortname}"',
                f'  secret = "{secret}"',
                "}",
                "",
            ]
        )
    return "\n".join(lines)


def edit_client(text: str, name: str, values: dict[str, str] | None) -> str:
    """Update a simple client block without replacing unrelated attributes or secrets.

    Nested blocks are deliberately rejected; they need native configuration editing.
    """
    matches = [match for match in CLIENT.finditer(text) if match[1] == name]
    if len(matches) != 1:
        raise ValueError("Client must have one unambiguous definition")
    match = matches[0]
    body = match[2]
    # Strip quoted strings and comments before checking nesting. Leave their
    # original bytes untouched unless the corresponding field is being edited.
    structural = re.sub(r'"(?:\\.|[^"\\])*"|#[^\n]*', "", body)
    if "{" in structural or "}" in structural:
        raise ValueError("Nested client configuration requires native editing")
    if values is None:
        return text[: match.start()] + text[match.end() :]
    for field, value in values.items():
        pattern = re.compile(r"(?m)^([ \t]*" + re.escape(field) + r"[ \t]*=)[^\n]*$")
        if len(pattern.findall(body)) > 1:
            raise ValueError("Duplicate client attributes require native editing")
        assignment = f'  {field} = "{value}"'
        body = (
            pattern.sub(lambda _, replacement=assignment: replacement, body)
            if pattern.search(body)
            else body + "\n" + assignment + "\n"
        )
    return text[: match.start(2)] + body + text[match.end(2) :]
