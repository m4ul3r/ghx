"""Headless entry point: ``ghx-agent``"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .paths import resolve_ghidra_install_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghx-agent",
        description="Run the ghx Agent Bridge (PyGhidra daemon)",
    )
    parser.add_argument(
        "binaries",
        nargs="*",
        help="Binary file paths to import into the project at startup",
    )
    parser.add_argument(
        "--instance-id",
        help="Instance ID for this bridge session (default: random)",
        default=None,
    )
    parser.add_argument(
        "--install-dir",
        help="Ghidra installation directory "
             "(defaults to $GHIDRA_INSTALL_DIR or /opt/ghidra_12.0.4_PUBLIC)",
        default=None,
    )
    parser.add_argument(
        "--project",
        help="Ghidra project directory (defaults to an ephemeral project under $GHX_CACHE_DIR/projects)",
        default=None,
    )
    parser.add_argument(
        "--project-name",
        help="Ghidra project name (defaults to 'ghx-<instance_id>')",
        default=None,
    )
    args = parser.parse_args(argv)

    install_dir = Path(args.install_dir) if args.install_dir else resolve_ghidra_install_dir()
    if install_dir is None:
        print(
            "error: could not locate Ghidra installation. Set GHIDRA_INSTALL_DIR "
            "or pass --install-dir.",
            file=sys.stderr,
        )
        return 2
    if not (install_dir / "Ghidra").is_dir():
        print(f"error: {install_dir} does not look like a Ghidra installation", file=sys.stderr)
        return 2
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(install_dir))

    # Make the ghx_agent_bridge daemon package importable when running from a
    # dev install (it lives outside src/ so uv tool install -e . does not
    # expose it via site-packages).
    plugin_dir = Path(__file__).resolve().parents[2] / "plugin"
    if plugin_dir.is_dir() and str(plugin_dir) not in sys.path:
        sys.path.insert(0, str(plugin_dir))

    from ghx_agent_bridge.bridge import start_headless

    start_headless(
        binaries=args.binaries,
        instance_id=args.instance_id,
        install_dir=install_dir,
        project_path=args.project,
        project_name=args.project_name,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
