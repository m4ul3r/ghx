"""Tests for the output rendering + spillover helpers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghx.output import (
    DEFAULT_SPILL_TOKEN_LIMIT,
    render_value,
    write_output_result,
)


def test_render_text_string_adds_trailing_newline():
    assert render_value("hello", "text") == "hello\n"


def test_render_text_already_newline_terminated():
    assert render_value("hi\n", "text") == "hi\n"


def test_render_json_formats_dict():
    out = render_value({"b": 2, "a": 1}, "json")
    parsed = json.loads(out)
    assert parsed == {"a": 1, "b": 2}
    # sort_keys=True
    assert out.index('"a"') < out.index('"b"')


def test_render_ndjson_flattens_list():
    out = render_value([{"x": 1}, {"x": 2}], "ndjson")
    lines = [line for line in out.splitlines() if line]
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"x": 1}
    assert json.loads(lines[1]) == {"x": 2}


def test_write_output_result_small_inline(tmp_cache):
    r = write_output_result(
        "short output",
        fmt="text",
        out_path=None,
        stem="unit",
    )
    assert r.rendered == "short output\n"
    assert r.spilled is False
    assert r.artifact is None


def test_write_output_result_spills_when_over_budget(tmp_cache):
    big = "x " * 50_000
    r = write_output_result(
        big,
        fmt="text",
        out_path=None,
        stem="unit",
        spill_token_limit=100,
    )
    assert r.spilled is True
    assert r.artifact is not None
    path = Path(r.artifact["artifact_path"])
    assert path.exists()
    assert path.read_text() == big + "\n"
    # Envelope should include all the fields we render.
    assert "path:" in r.rendered
    assert "tokens:" in r.rendered
    assert "sha256:" in r.rendered


def test_write_output_result_explicit_out_path(tmp_path):
    dest = tmp_path / "result.json"
    r = write_output_result(
        {"a": 1},
        fmt="json",
        out_path=dest,
        stem="unit",
    )
    assert dest.exists()
    assert json.loads(dest.read_text()) == {"a": 1}
    # Explicit --out never marks as "spilled" even though the content moved to disk.
    assert r.artifact["spilled"] is False
    assert r.artifact["artifact_path"] == str(dest)


def test_default_spill_token_limit_stable():
    # Skills and docs pin on this number; alert if it drifts.
    assert DEFAULT_SPILL_TOKEN_LIMIT == 10_000
