"""ghx_agent_bridge - PyGhidra-backed daemon for the ghx CLI.

This package is not a Ghidra extension plugin (that is phase 2).  It is a
long-running Python process started by ``ghx-agent`` that holds a JVM and a
Ghidra Project open and exposes a Unix-socket JSON protocol consumed by the
``ghx`` CLI.
"""
