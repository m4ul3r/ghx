"""Tests for ghx.paths."""
from __future__ import annotations

from pathlib import Path

from ghx import paths


def test_cache_home_respects_env(tmp_cache):
    assert paths.cache_home() == tmp_cache


def test_bridge_paths_with_instance(tmp_cache):
    reg = paths.bridge_registry_path("abc123")
    sock = paths.bridge_socket_path("abc123")
    assert reg.name == "abc123.json"
    assert sock.name == "abc123.sock"
    assert reg.parent == paths.instances_dir()
    assert sock.parent == paths.instances_dir()


def test_bridge_paths_without_instance(tmp_cache):
    reg = paths.bridge_registry_path(None)
    sock = paths.bridge_socket_path(None)
    assert reg.name == f"{paths.PLUGIN_NAME}.json"
    assert sock.name == f"{paths.PLUGIN_NAME}.sock"
    assert reg.parent == tmp_cache
    assert sock.parent == tmp_cache


def test_projects_dir_avoids_dot_elements_on_default_cache(monkeypatch):
    # The default cache home (~/.cache/ghx) contains the '.cache' element, which
    # Ghidra's ProjectLocator rejects. projects_dir() must NOT return a path with
    # any dot-prefixed element, or the daemon fails to open an ephemeral project.
    monkeypatch.delenv("GHX_CACHE_DIR", raising=False)
    pd = paths.projects_dir()
    assert not any(part.startswith(".") for part in pd.resolve().parts), pd


def test_projects_dir_uses_clean_cache_dir(tmp_path, monkeypatch):
    # A GHX_CACHE_DIR with no dotted element hosts projects directly under it.
    monkeypatch.setenv("GHX_CACHE_DIR", str(tmp_path))
    assert paths.projects_dir() == tmp_path / "projects"


def test_resolve_ghidra_install_dir_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(paths, "DEFAULT_GHIDRA_INSTALL_DIR", str(tmp_path / "nope"))
    assert paths.resolve_ghidra_install_dir() is None


def test_resolve_ghidra_install_dir_via_env(monkeypatch, tmp_path):
    fake = tmp_path / "ghidra"
    (fake / "Ghidra").mkdir(parents=True)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(fake))
    assert paths.resolve_ghidra_install_dir() == fake
