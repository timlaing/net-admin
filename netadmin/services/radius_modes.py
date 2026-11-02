"""Conservative FreeRADIUS 3 EAP configuration edits with reversible method blocks."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

MODES = {"mschapv2": "EAP-MSCHAPv2", "peap": "PEAP with MSCHAPv2", "tls": "EAP-TLS"}
DISABLED = "#NETADMIN-EAP-OFF "
INNER = "netadmin_inner"
INNER_MARKER = "# NetAdmin inner EAP instance\n"
TLS_CONFIG_PREFIX = "tls-config "
TLS_METHODS = {"tls", "peap", "ttls", "fast", "teap"}


@dataclass(frozen=True)
class Section:
    """Source spans, never public configuration values."""

    name: str
    start: int
    opening: int
    end: int
    depth: int


def _mask(text: str) -> str:
    """Keep positions while masking comments, quotes and variable expansions."""
    result = list(text)
    token = re.compile(
        r"""\# [^\n]* | " (?:[^"\\]|\\.)* " | ' (?:[^'\\]|\\.)* ' | \$\{[^}\n]*\}""", re.X
    )
    for match in token.finditer(text):
        result[match.start() : match.end()] = ["\n" if c == "\n" else " " for c in match.group()]
    return "".join(result)


def _sections(text: str) -> list[Section]:
    masked = _mask(text)
    stack: list[tuple[str, int, int]] = []
    result = []
    for index, char in enumerate(masked):
        if char == "{":
            start = masked.rfind("\n", 0, index) + 1
            name = masked[start:index].strip()
            stack.append((name, start, index))
        elif char == "}":
            if not stack:
                raise ValueError("Unbalanced configuration")
            name, start, opening = stack.pop()
            result.append(Section(name, start, opening, index + 1, len(stack)))
    if stack:
        raise ValueError("Unbalanced configuration")
    return sorted(result, key=lambda section: section.start)


def _outer(text: str) -> Section:
    roots = [s for s in _sections(text) if s.depth == 0]
    if [s.name for s in roots] not in (["eap"], ["eap", f"eap {INNER}"]):
        raise ValueError("A single standard eap module is required")
    if "$INCLUDE" in _mask(text):
        raise ValueError("Included EAP configuration requires native editing")
    return roots[0]


def _children(text: str, parent: Section) -> list[Section]:
    return [
        s
        for s in _sections(text)
        if parent.opening < s.start < parent.end and s.depth == parent.depth + 1
    ]


def _setting(text: str, parent: Section, key: str, value: str | None = None) -> str:
    body = list(text[parent.opening + 1 : parent.end - 1])
    for child in _children(text, parent):
        left = child.start - parent.opening - 1
        right = child.end - parent.opening - 1
        body[left:right] = ["\n" if c == "\n" else " " for c in body[left:right]]
    matches = list(re.finditer(rf"(?m)^[ \t]*{key}[ \t]*=([^\n]*)", _mask("".join(body))))
    if len(matches) > 1:
        raise ValueError("Duplicate EAP setting")
    if matches:
        match = matches[0]
        start = parent.opening + 1 + match.start()
        end = parent.opening + 1 + match.end()
        if value is None:
            parsed = re.fullmatch(
                rf'\s*{key}\s*=\s*"?([A-Za-z0-9_-]+)"?\s*(?:#.*)?', text[start:end]
            )
            if not parsed:
                raise ValueError("Unsupported EAP setting")
            return parsed.group(1)
        return text[:start] + f"\t{key} = {value}" + text[end:]
    if value is None:
        return ""
    return text[: parent.opening + 1] + f"\n\t{key} = {value}\n" + text[parent.opening + 1 :]


def revision(eap: str, inner: str) -> str:
    """Detect edits made since the operator loaded the form."""
    return hashlib.sha256((eap + "\0" + inner).encode()).hexdigest()


def inventory(eap: str, inner: str) -> dict[str, object]:
    """Report enabled module methods; no keys, certificates or passwords."""
    outer = _outer(eap)
    methods = [s.name for s in _children(eap, outer) if not s.name.startswith(TLS_CONFIG_PREFIX)]
    if any(not re.fullmatch(r"[a-z0-9_-]+", name) for name in methods):
        raise ValueError("Complex EAP methods require native editing")
    return {
        "available": True,
        "enabled": [name for name in MODES if name in methods],
        "other_methods": [name for name in methods if name not in MODES],
        "preferred": _setting(eap, outer, "default_eap_type"),
        "uses_certificates": bool(TLS_METHODS.intersection(methods)),
        "revision": revision(eap, inner),
    }


def _inner(text: str) -> str:
    sections = _sections(text)
    if len([s for s in sections if s.depth == 0 and s.name == "server inner-tunnel"]) != 1:
        raise ValueError("A standard inner-tunnel server is required")
    # Match module calls only: never comments, strings, Auth-Type names or policies.
    pattern = re.compile(
        rf"(?m)^(?P<indent>[ \t]*)(?P<optional>-?)(?:eap|{INNER})(?P<tail>[ \t]*(?:\{{|$))"
    )
    matches = list(pattern.finditer(_mask(text)))
    contexts = []
    for match in matches:
        parents = [s.name for s in sections if s.opening < match.start() < s.end]
        contexts.append(
            next(
                (
                    name
                    for name in ("authorize", "authenticate", "post-auth", "post-proxy")
                    if name in parents
                ),
                "",
            )
        )
    if (
        contexts.count("authorize") != 1
        or contexts.count("authenticate") != 1
        or contexts.count("post-auth") > 1
        or contexts.count("post-proxy") > 1
        or "" in contexts
    ):
        raise ValueError("Unsupported inner EAP module calls")
    for match in reversed(matches):
        start = match.start() + len(match.group("indent")) + len(match.group("optional"))
        end = match.end() - len(match.group("tail"))
        text = text[:start] + INNER + text[end:]
    return text


def configure(eap: str, inner: str, enabled: list[str], preferred: str) -> tuple[str, str]:
    """Keep TLS policy and disabled blocks; isolate inner MSCHAPv2 from outer choices."""
    if not enabled or len(enabled) != len(set(enabled)) or set(enabled) - MODES.keys():
        raise ValueError("Select at least one supported authentication mode")
    if preferred not in enabled:
        raise ValueError("The preferred mode must be enabled")
    _outer(eap)
    if INNER_MARKER in eap:
        eap = eap.split(INNER_MARKER, 1)[0]
    eap = "".join(line.removeprefix(DISABLED) for line in eap.splitlines(keepends=True))
    outer = _outer(eap)
    methods = {s.name: s for s in _children(eap, outer) if not s.name.startswith(TLS_CONFIG_PREFIX)}
    if len(methods) != len(
        [s for s in _children(eap, outer) if not s.name.startswith(TLS_CONFIG_PREFIX)]
    ):
        raise ValueError("Duplicate EAP method blocks")
    if not set(MODES) <= methods.keys():
        raise ValueError("TLS, PEAP and MSCHAPv2 templates must exist before management")
    mschap = eap[methods["mschapv2"].start : methods["mschapv2"].end]
    for name, section in sorted(methods.items(), key=lambda item: item[1].start, reverse=True):
        block = eap[section.start : section.end]
        block = _method_settings(name, block)
        if name not in enabled:
            block = "".join(DISABLED + line for line in block.splitlines(keepends=True))
        eap = eap[: section.start] + block + eap[section.end :]
    eap = _setting(eap, _outer(eap), "default_eap_type", preferred)
    eap = (
        eap.rstrip()
        + f"\n\n{INNER_MARKER}eap {INNER} {{\n\tdefault_eap_type = mschapv2\n{mschap}\n}}\n"
    )
    return eap, _inner(inner)


def _method_settings(name: str, block: str) -> str:
    """Apply the fixed settings required by each selectable authentication method."""
    if name == "peap":
        for key, value in (
            ("default_eap_type", "mschapv2"),
            ("virtual_server", "inner-tunnel"),
            ("use_tunneled_reply", "yes"),
        ):
            block = _setting(block, _sections(block)[0], key, value)
    if name == "tls":
        block = _setting(block, _sections(block)[0], "configurable_client_cert", "no")
    return block
