from __future__ import annotations

import os
import platform
import tempfile
from pathlib import Path


PLUGIN_NAME = "ghx_agent_bridge"
DEFAULT_GHIDRA_INSTALL_DIR = "/opt/ghidra_12.0.4_PUBLIC"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def claude_home() -> Path:
    env = os.environ.get("CLAUDE_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".claude"


def cache_home() -> Path:
    env = os.environ.get("GHX_CACHE_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Caches" / "ghx"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ghx"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "ghx"
    return home / ".cache" / "ghx"


def instances_dir() -> Path:
    return cache_home() / "instances"


def bridge_registry_path(instance_id: str | None = None) -> Path:
    if instance_id is None:
        return cache_home() / f"{PLUGIN_NAME}.json"
    return instances_dir() / f"{instance_id}.json"


def bridge_socket_path(instance_id: str | None = None) -> Path:
    if instance_id is None:
        return cache_home() / f"{PLUGIN_NAME}.sock"
    return instances_dir() / f"{instance_id}.sock"


def projects_dir() -> Path:
    return cache_home() / "projects"


def spill_root() -> Path:
    root = Path(tempfile.gettempdir()) / "ghx-spills"
    root.mkdir(parents=True, exist_ok=True)
    return root


def plugin_source_dir() -> Path:
    return repo_root() / "plugin" / PLUGIN_NAME


def resolve_ghidra_install_dir() -> Path | None:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env).expanduser()
        if (p / "Ghidra").is_dir():
            return p
    default = Path(DEFAULT_GHIDRA_INSTALL_DIR)
    if (default / "Ghidra").is_dir():
        return default
    return None


def claude_skills_dir() -> Path:
    return claude_home() / "skills"
