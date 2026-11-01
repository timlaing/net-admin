"""Loss-minimizing parsers and transforms for FreeRADIUS files backends."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

ENTRY_START = re.compile(r"^(?![\s#])([A-Za-z0-9_.@-]+)\s++(.*)$")
PASSWORD = re.compile(r'(Cleartext-Password|Crypt-Password)\s*:=\s*"([^"]*)"')
ROLE = re.compile(r'Filter-Id\s*:?=\s*"([^"]+)"')
POOL = re.compile(r'Framed-Pool\s*+=?\s*+"([^"]+)"')
CLIENT = re.compile(r"(?ms)^client\s+([A-Za-z0-9_.-]+)\s*\{(.*?)^\}")


@dataclass(frozen=True, slots=True)
class RadiusUser:
    """Safe view of a file-backed user."""

    username: str
    password_kind: str
    role: str
    disabled: bool
    source: str


@dataclass(frozen=True, slots=True)
class RadiusClient:
    """Safe view of a RADIUS client; secrets are intentionally absent."""

    name: str
    address: str
    shortname: str


def user_blocks(text: str) -> list[tuple[str, str]]:
    """Split active top-level users into complete blocks."""
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        match = ENTRY_START.match(lines[index])
        if not match or match.group(1) == "DEFAULT":
            index += 1
            continue
        end = index + 1
        while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
            end += 1
        blocks.append((match.group(1), "".join(lines[index:end])))
        index = end
    return blocks


def parse_authorize(text: str, source: str) -> list[RadiusUser]:
    """Parse user metadata without returning passwords or hashes."""
    users = []
    for username, block in user_blocks(text):
        password = PASSWORD.search(block)
        if not password:
            continue
        role = ROLE.search(block)
        users.append(
            RadiusUser(
                username=username,
                password_kind=password.group(1),
                role=role.group(1) if role else "",
                disabled=False,
                source=source,
            )
        )
    return users


def _pool_role(block: str, admin_pools: set[str], admin_role: str, standard_role: str) -> str:
    """Pool-derived role for a block that carries no explicit role attribute."""
    pool = POOL.search(block)
    return admin_role if pool and pool.group(1) in admin_pools else standard_role


def _migrate_block(
    block: str,
    password_hasher: Callable[[str], str],
    admin_pools: set[str],
    admin_role: str,
    standard_role: str,
) -> tuple[str, bool]:
    """Transform one legacy block; returns the new block and whether it changed."""
    password = PASSWORD.search(block)
    if not password:
        return block, False
    changed = block
    if password.group(1) == "Cleartext-Password":
        hashed = password_hasher(password.group(2))
        changed = PASSWORD.sub(f'Crypt-Password := "{hashed}"', changed, count=1)
    if not ROLE.search(changed):
        role = _pool_role(changed, admin_pools, admin_role, standard_role)
        first, separator, rest = changed.partition("\n")
        first = f'{first.rstrip()}, Filter-Id := "{role}"'
        changed = first + (separator + rest if separator else "\n")
    return changed, changed != block


def migrate_authorize(
    text: str,
    password_hasher: Callable[[str], str],
    admin_pools: set[str],
    admin_role: str,
    standard_role: str,
) -> tuple[str, list[str]]:
    """Hash cleartext passwords and add missing role attributes in-place."""
    migrated: list[str] = []
    output = text
    for username, block in user_blocks(text):
        changed, did_change = _migrate_block(
            block, password_hasher, admin_pools, admin_role, standard_role
        )
        if did_change:
            output = output.replace(block, changed, 1)
            migrated.append(username)
    return output, migrated


def migrate_to_managed(
    text: str,
    password_hasher: Callable[[str], str],
    admin_pools: set[str],
    admin_role: str,
    standard_role: str,
) -> tuple[str, dict[str, tuple[str, str, bool]]]:
    """Remove file-backed users from a legacy file and return managed entries."""
    remaining = text
    managed: dict[str, tuple[str, str, bool]] = {}
    for username, block in user_blocks(text):
        password = PASSWORD.search(block)
        if not password:
            continue
        password_hash = (
            password_hasher(password.group(2))
            if password.group(1) == "Cleartext-Password"
            else password.group(2)
        )
        current_role = ROLE.search(block)
        if current_role:
            role = current_role.group(1)
        else:
            role = _pool_role(block, admin_pools, admin_role, standard_role)
        managed[username] = (password_hash, role, False)
        remaining = remaining.replace(block, "", 1)
    return remaining, managed


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
