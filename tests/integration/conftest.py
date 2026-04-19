"""Integration tests boot a real ghx-agent; gated on GHIDRA_INSTALL_DIR."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ghx import paths, transport


def _resolve_ghidra_dir() -> Path | None:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and (Path(env) / "Ghidra").is_dir():
        return Path(env)
    default = Path("/opt/ghidra_12.0.4_PUBLIC")
    if (default / "Ghidra").is_dir():
        return default
    return None


@pytest.fixture(scope="session")
def ghidra_dir() -> Path:
    gd = _resolve_ghidra_dir()
    if gd is None:
        pytest.skip("no Ghidra installation found (set GHIDRA_INSTALL_DIR)")
    return gd


@pytest.fixture(scope="session")
def ghx_agent_cmd() -> list[str]:
    """Return the command to launch ghx-agent, preferring the installed script."""
    exe_dir = Path(sys.executable).parent
    candidate = exe_dir / "ghx-agent"
    if candidate.exists():
        return [str(candidate)]
    return [sys.executable, "-m", "ghx.headless"]


@pytest.fixture(scope="session")
def ghx_cli_cmd() -> list[str]:
    exe_dir = Path(sys.executable).parent
    candidate = exe_dir / "ghx"
    if candidate.exists():
        return [str(candidate)]
    return [sys.executable, "-m", "ghx.cli"]


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Give each test a private GHX_CACHE_DIR so daemons don't collide."""
    monkeypatch.setenv("GHX_CACHE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def running_agent(ghidra_dir, ghx_agent_cmd, isolated_cache, tmp_path):
    """Spawn a real ghx-agent and wait for it to register."""
    instance_id = "it0001"
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    log_path = tmp_path / "agent.log"
    env = {**os.environ, "GHIDRA_INSTALL_DIR": str(ghidra_dir),
           "GHX_CACHE_DIR": str(isolated_cache)}
    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        ghx_agent_cmd
        + ["--instance-id", instance_id,
           "--project", str(project_dir),
           "--project-name", "ghx-it"],
        start_new_session=True,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    log_file.close()

    reg = paths.bridge_registry_path(instance_id)
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if reg.exists():
            try:
                inst = transport._load_instance(reg)
            except Exception:
                inst = None
            if inst is not None:
                break
        if proc.poll() is not None:
            pytest.fail(
                f"ghx-agent exited with code {proc.returncode} before registering; "
                f"log at {log_path}"
            )
        time.sleep(0.3)
    else:
        proc.terminate()
        pytest.fail(f"ghx-agent did not register within 60s; log at {log_path}")

    yield instance_id

    try:
        transport.send_request("shutdown", instance_id=instance_id, timeout=5.0)
    except Exception:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
