"""Fallback entry point: ``python -m ghx_agent_bridge``."""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ghx_agent_bridge",
        description="Run the ghx Agent Bridge (PyGhidra daemon)",
    )
    parser.add_argument("binaries", nargs="*")
    parser.add_argument("--instance-id", default=None)
    parser.add_argument("--install-dir", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--project-name", default=None)
    args = parser.parse_args()

    from pathlib import Path
    from .bridge import start_headless

    install_dir = Path(args.install_dir) if args.install_dir else None
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
