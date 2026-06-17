"""Sticky CLI pins — a persisted default instance/target selector.

`ghx instance use <id>` / `ghx target use <selector>` write here; subsequent
op commands fall back to these when no explicit ``--instance`` / ``-t`` is
given. Stored as a small JSON object at :func:`ghx.paths.pin_path`.
"""
from __future__ import annotations

import contextlib
import json
from typing import Any

from .paths import pin_path


def read_pins() -> dict[str, Any]:
    """Return the pin mapping, or ``{}`` if missing/corrupt."""
    try:
        data = json.loads(pin_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_pins(data: dict[str, Any]) -> None:
    path = pin_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def get_instance() -> str | None:
    value = read_pins().get("instance")
    return str(value) if value else None


def get_target() -> str | None:
    value = read_pins().get("target")
    return str(value) if value else None


def set_instance(instance_id: str) -> None:
    data = read_pins()
    data["instance"] = str(instance_id)
    _write_pins(data)


def set_target(selector: str) -> None:
    data = read_pins()
    data["target"] = str(selector)
    _write_pins(data)


def clear_instance() -> bool:
    """Remove the instance pin. Returns True if one was set."""
    data = read_pins()
    had = "instance" in data
    data.pop("instance", None)
    if had:
        if data:
            _write_pins(data)
        else:
            with contextlib.suppress(OSError):
                pin_path().unlink()
    return had


def clear_target() -> bool:
    """Remove the target pin. Returns True if one was set."""
    data = read_pins()
    had = "target" in data
    data.pop("target", None)
    if had:
        if data:
            _write_pins(data)
        else:
            with contextlib.suppress(OSError):
                pin_path().unlink()
    return had
