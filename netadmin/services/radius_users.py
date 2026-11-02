"""RADIUS user records with paired credentials and lossless reply attributes."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

ENTRY = re.compile(r"^(?![\s#])([A-Za-z0-9_.@-]+)\s++(.*)$")
PASSWORD = re.compile(
    r'(Cleartext-Password|Crypt-Password|NT-Password)\s*:=\s*("(?:[^"\\]|\\.)*"|0x[0-9a-fA-F]+)'
)
ROLE = re.compile(r'Filter-Id\s*:?=\s*"([^"\n]+)"')
POOL = re.compile(r'Framed-Pool\s*+=?\s*+"([^"\n]+)"')
ATTRIBUTE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_:-]*)\s*(?P<op>:=|==|!=|=~|!~|\+=|-=|<=|>=|=|<|>)\s*"
    r'(?P<value>"(?:[^"\\]|\\.)*"|[^,\s#]+)'
)
PASSWORD_NAMES = {"Cleartext-Password", "Crypt-Password", "NT-Password"}
DISABLED = "#DISABLED "


@dataclass(frozen=True, slots=True, repr=False)
class PasswordHashes:
    """Private credentials. Empty members indicate a legacy single-format record."""

    crypt: str = ""
    nt: str = ""

    @property
    def kind(self) -> str:
        """Public format names, with no credential values."""
        return " + ".join(
            name
            for name, value in [("Crypt-Password", self.crypt), ("NT-Password", self.nt)]
            if value
        )


@dataclass(frozen=True, slots=True, repr=False)
class ManagedUser:
    """Keep unrelated native check and reply attributes when credentials change."""

    passwords: PasswordHashes
    role: str
    disabled: bool = False
    checks: tuple[str, ...] = ()
    replies: str = field(default="", repr=False)
    comment: str = ""


@dataclass(frozen=True, slots=True)
class RadiusUser:
    """Safe inventory view."""

    username: str
    password_kind: str
    role: str
    disabled: bool
    source: str


def user_blocks(text: str) -> list[tuple[str, str]]:
    """Split complete user stanzas, keeping their indented replies."""
    lines = text.splitlines(keepends=True)
    blocks = []
    index = 0
    while index < len(lines):
        match = ENTRY.match(lines[index])
        if not match or match.group(1) == "DEFAULT":
            index += 1
            continue
        end = index + 1
        while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
            end += 1
        blocks.append((match.group(1), "".join(lines[index:end])))
        index = end
    return blocks


def _attributes(block: str) -> tuple[list[re.Match[str]], str]:
    """Parse one-line check items; refuse ambiguous continuations before writes."""
    header = block.splitlines()[0]
    entry = ENTRY.fullmatch(header)
    if entry is None:
        raise ValueError("Unsupported user entry")
    remaining = entry.group(2).strip()
    attributes = []
    while remaining and not remaining.startswith("#"):
        match = ATTRIBUTE.match(remaining)
        if match is None:
            raise ValueError("Complex user check items require native editing")
        attributes.append(match)
        remaining = remaining[match.end() :].lstrip()
        if remaining.startswith(","):
            remaining = remaining[1:].lstrip()
            if not remaining or remaining.startswith("#"):
                raise ValueError("Multiline user check items require native editing")
        elif remaining and not remaining.startswith("#"):
            raise ValueError("Ambiguous user check items")
    return attributes, remaining


def _value(attribute: re.Match[str]) -> str:
    value = attribute.group("value")
    return str(json.loads(value)) if value.startswith('"') else value


def _check_items(
    attributes: list[re.Match[str]], default_role: str
) -> tuple[dict[str, str], list[str], str]:
    passwords = {}
    checks = []
    roles = [
        item
        for item in attributes
        if item.group("name") == "Filter-Id" and item.group("op") == ":="
    ]
    if len(roles) > 1:
        raise ValueError("Multiple role assignments require native editing")
    role = _value(roles[0]) if roles else default_role
    for attribute in attributes:
        name = attribute.group("name")
        if name in PASSWORD_NAMES:
            if name in passwords or attribute.group("op") != ":=":
                raise ValueError("Ambiguous password attributes")
            passwords[name] = _value(attribute)
        elif attribute not in roles:
            checks.append(attribute.group(0))
    return passwords, checks, role


def _credentials(
    passwords: dict[str, str], hasher: Callable[[str], PasswordHashes | str] | None
) -> PasswordHashes:
    if "Cleartext-Password" in passwords:
        if hasher is None:
            raise ValueError("Managed cleartext entries require migration")
        hashed = hasher(passwords["Cleartext-Password"])
        return PasswordHashes(hashed) if isinstance(hashed, str) else hashed
    nt = passwords.get("NT-Password", "").removeprefix("0x")
    if nt and not re.fullmatch(r"[0-9a-fA-F]{32}", nt):
        raise ValueError("Invalid NT password encoding")
    return PasswordHashes(passwords.get("Crypt-Password", ""), nt.lower())


def _record(
    block: str,
    hasher: Callable[[str], PasswordHashes | str] | None,
    default_role: str,
) -> ManagedUser:
    attributes, comment = _attributes(block)
    passwords, checks, role = _check_items(attributes, default_role)
    hashes = _credentials(passwords, hasher)
    if not hashes.kind:
        raise ValueError("User has no supported password attribute")
    _, separator, replies = block.partition("\n")
    return ManagedUser(
        hashes,
        role,
        checks=tuple(checks),
        replies=separator + replies,
        comment=comment,
    )


def managed_entries(text: str) -> dict[str, ManagedUser]:
    """Read both old crypt-only entries and paired entries without losing state."""
    disabled = set()
    decoded = []
    for line in text.splitlines(keepends=True):
        if line.startswith(DISABLED):
            line = line.removeprefix(DISABLED)
            match = ENTRY.match(line)
            if match:
                disabled.add(match.group(1))
        decoded.append(line)
    normalized = "".join(decoded)
    remaining = normalized
    entries = {}
    for username, block in user_blocks(normalized):
        if username in entries:
            raise ValueError("Duplicate managed users require native editing")
        record = _record(block, None, "netadmin-standard")
        entries[username] = ManagedUser(
            record.passwords,
            record.role,
            username in disabled,
            record.checks,
            record.replies,
            record.comment,
        )
        remaining = remaining.replace(block, "", 1)
    if any(line.strip() and not line.lstrip().startswith("#") for line in remaining.splitlines()):
        raise ValueError("Unsupported managed user content; no changes were applied")
    return entries


def render_users(entries: dict[str, ManagedUser]) -> str:
    """Write paired check attributes and preserve native reply settings."""
    blocks = ["# Managed by NetAdmin. Password hashes are never returned by the API.\n"]
    for username, user in sorted(entries.items()):
        checks = []
        if user.passwords.crypt:
            checks.append(f"Crypt-Password := {json.dumps(user.passwords.crypt)}")
        if user.passwords.nt:
            checks.append(f"NT-Password := 0x{user.passwords.nt}")
        checks.append(f"Filter-Id := {json.dumps(user.role)}")
        checks.extend(user.checks)
        block = f"{username} {', '.join(checks)}"
        if user.comment:
            block += " " + user.comment
        block += user.replies
        if not block.endswith("\n"):
            block += "\n"
        if user.disabled:
            block = "".join(DISABLED + line for line in block.splitlines(keepends=True))
        blocks.append(block)
    return "".join(blocks)


def parse_users(text: str) -> list[dict[str, str | bool]]:
    """Expose metadata only, including missing hashes requiring a password reset."""
    return [
        {
            "username": name,
            "role": user.role,
            "disabled": user.disabled,
            "password_kind": user.passwords.kind,
            "needs_password_reset": not (user.passwords.crypt and user.passwords.nt),
            "mschapv2_ready": bool(user.passwords.nt),
        }
        for name, user in managed_entries(text).items()
    ]


def parse_authorize(text: str, source: str) -> list[RadiusUser]:
    """Describe legacy formats without returning password values."""
    users = []
    for username, block in user_blocks(text):
        kinds = {match.group(1) for match in PASSWORD.finditer(block)}
        if not kinds:
            continue
        role = ROLE.search(block)
        users.append(
            RadiusUser(
                username, " + ".join(sorted(kinds)), role.group(1) if role else "", False, source
            )
        )
    return users


def migrate_to_managed(
    text: str,
    password_hasher: Callable[[str], PasswordHashes | str],
    admin_pools: set[str],
    admin_role: str,
    standard_role: str,
) -> tuple[str, dict[str, ManagedUser]]:
    """Generate both hashes from cleartext; retain existing hashes and all replies."""
    remaining = text
    entries = {}
    for username, block in user_blocks(text):
        if not PASSWORD.search(block):
            continue
        if username in entries:
            raise ValueError("Duplicate legacy users require native editing")
        pool = POOL.search(block)
        role = admin_role if pool and pool.group(1) in admin_pools else standard_role
        entries[username] = _record(block, password_hasher, role)
        remaining = remaining.replace(block, "", 1)
    return remaining, entries


def migrate_authorize(
    text: str,
    password_hasher: Callable[[str], PasswordHashes | str],
    admin_pools: set[str],
    admin_role: str,
    standard_role: str,
) -> tuple[str, list[str]]:
    """Preview or update credential/role fields while keeping the native stanzas."""
    _, entries = migrate_to_managed(text, password_hasher, admin_pools, admin_role, standard_role)
    output = text
    changed = []
    for username, block in user_blocks(text):
        if username not in entries:
            continue
        rendered = render_users({username: entries[username]}).split("\n", 1)[1]
        if rendered != block:
            output = output.replace(block, rendered, 1)
            changed.append(username)
    return output, changed
