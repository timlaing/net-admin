"""Guards for the Home Assistant add-on files the Supervisor parses.

The Supervisor builds the add-on's Configuration form from ``config.yaml``'s
``schema`` plus ``translations/<language>.yaml``, and it splits ``list(...)``
types on ``|``. Nothing else in CI reads these files, so a comma-separated list
silently becomes a single choice that rejects the stored default — which stops
the Supervisor from writing ``/data/options.json`` at start-up — and missing
translations leave raw option keys as labels with no help text.
"""

from pathlib import Path
from typing import Any

import yaml

ADDON_DIR = Path(__file__).resolve().parents[1] / "home-assistant" / "netadmin"


def load_yaml(name: str) -> dict[str, Any]:
    """Parse one of the add-on's YAML files."""
    with (ADDON_DIR / name).open(encoding="utf-8") as handle:
        data: dict[str, Any] = yaml.safe_load(handle)
    return data


def list_choices(schema_type: str) -> list[str]:
    """Split a ``list(...)`` type the way the Supervisor's parser does."""
    return schema_type.removeprefix("list(").removesuffix(")").split("|")


def test_defaults_are_declared_and_required_options_have_them() -> None:
    config = load_yaml("config.yaml")
    options: dict[str, Any] = config["options"]
    schema: dict[str, Any] = config["schema"]

    assert set(options) <= set(schema), "default for an option missing from schema"
    missing = {key for key, typ in schema.items() if not str(typ).endswith("?")}
    assert not missing - set(options), "required option without a default"


def test_list_options_are_pipe_separated_choices() -> None:
    config = load_yaml("config.yaml")
    options: dict[str, Any] = config["options"]

    checked = 0
    for key, schema_type in config["schema"].items():
        if not str(schema_type).startswith("list("):
            continue
        checked += 1
        choices = list_choices(str(schema_type))
        assert len(choices) > 1, f"{key}: {schema_type!r} is a single choice, use list(a|b)"
        assert all(choice and choice.strip() == choice for choice in choices), (
            f"{key}: {schema_type!r} has a blank or padded choice"
        )
        assert options[key] in choices, (
            f"{key}: default {options[key]!r} is not one of {choices}, "
            "the Supervisor rejects it and the add-on cannot start"
        )

    assert checked, "expected at least one list(...) option in the schema"


def test_translations_describe_every_option() -> None:
    config = load_yaml("config.yaml")
    translations: dict[str, Any] = load_yaml("translations/en.yaml")["configuration"]

    for key in config["schema"]:
        entry = translations.get(key)
        assert isinstance(entry, dict), f"no translation entry for {key}"
        assert entry.get("name"), f"translation for {key} has no name"
        assert entry.get("description"), f"translation for {key} has no description"


def test_ingress_login_default_preserves_access_for_radius_users() -> None:
    config = load_yaml("config.yaml")
    assert config["options"]["ingress_require_login"] is True
    assert config["schema"]["ingress_require_login"] == "bool"
    assert config["panel_admin"] is False
