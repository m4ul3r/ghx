"""Shared test fixtures for ghx unit tests."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Point GHX_CACHE_DIR at a temp directory so tests don't touch ~/.cache."""
    monkeypatch.setenv("GHX_CACHE_DIR", str(tmp_path))
    return tmp_path
