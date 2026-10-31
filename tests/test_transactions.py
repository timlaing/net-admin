"""Transactional file update tests."""

from pathlib import Path

import pytest

from netadmin.agents.common import validated_transaction


def test_transaction_rolls_back_validation_failure(tmp_path: Path) -> None:
    first = tmp_path / "first.conf"
    second = tmp_path / "second.conf"
    first.write_text("original-one")
    second.write_text("original-two")

    def fail() -> None:
        raise RuntimeError("invalid")

    with pytest.raises(RuntimeError):
        validated_transaction(
            {first: "changed-one", second: "changed-two"}, fail, [], allowed_roots=(tmp_path,)
        )
    assert first.read_text() == "original-one"
    assert second.read_text() == "original-two"


@pytest.mark.parametrize("escape", ["absolute", "parent", "symlink"])
def test_transaction_rejects_escape_before_writing(tmp_path: Path, escape: str) -> None:
    root = tmp_path / "service"
    root.mkdir()
    safe = root / "safe.conf"
    safe.write_text("unchanged")
    outside = tmp_path / "outside.conf"
    outside.write_text("protected")
    target = outside
    if escape == "parent":
        target = root / ".." / outside.name
    elif escape == "symlink":
        target = root / "link.conf"
        target.symlink_to(outside)
    with pytest.raises(ValueError, match="Transaction path"):
        validated_transaction(
            {safe: "changed", target: "overwritten"},
            lambda: pytest.fail("Validation must not run for an unsafe path"),
            [],
            allowed_roots=(root,),
        )
    assert safe.read_text() == "unchanged"
    assert outside.read_text() == "protected"


def test_transaction_supports_nested_includes(tmp_path: Path) -> None:
    nested = tmp_path / "includes"
    nested.mkdir()
    target = nested / "pool.conf"
    validated_transaction({target: "new pool"}, lambda: None, [], allowed_roots=(tmp_path,))
    assert target.read_text() == "new pool"
