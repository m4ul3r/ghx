"""Tests for sticky CLI pins (instance/target default selection)."""
from __future__ import annotations

from ghx import pins
from ghx.paths import pin_path


def test_pins_roundtrip(tmp_cache):
    assert pins.get_instance() is None
    assert pins.get_target() is None

    pins.set_instance("aa11")
    pins.set_target("active")
    assert pins.get_instance() == "aa11"
    assert pins.get_target() == "active"

    # Clearing the instance leaves the target pin intact.
    assert pins.clear_instance() is True
    assert pins.get_instance() is None
    assert pins.get_target() == "active"

    # Clearing is idempotent and reports whether anything was set.
    assert pins.clear_target() is True
    assert pins.clear_target() is False
    assert pins.get_target() is None


def test_set_overwrites(tmp_cache):
    pins.set_instance("first")
    pins.set_instance("second")
    assert pins.get_instance() == "second"


def test_read_pins_corrupt_returns_empty(tmp_cache):
    path = pin_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("this is not json{", encoding="utf-8")
    assert pins.read_pins() == {}
    assert pins.get_instance() is None
    assert pins.get_target() is None
