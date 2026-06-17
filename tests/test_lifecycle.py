"""Unit tests for instance-prune idle selection (no daemon required)."""
from __future__ import annotations

import datetime as dt

from ghx import cli, transport


def _inst(instance_id: str, *, last_active: str | None = None, started_at: str | None = None):
    meta = {}
    if last_active is not None:
        meta["last_active"] = last_active
    if started_at is not None:
        meta["started_at"] = started_at
    return transport.BridgeInstance(
        pid=1,
        socket_path=cli.Path(f"/tmp/{instance_id}.sock"),
        registry_path=cli.Path(f"/tmp/{instance_id}.json"),
        plugin_name="ghx_agent_bridge",
        plugin_version="test",
        started_at=started_at,
        meta=meta,
        instance_id=instance_id,
    )


def _iso(seconds_ago: float, now: dt.datetime) -> str:
    return (now - dt.timedelta(seconds=seconds_ago)).isoformat()


def test_idle_seconds_prefers_last_active():
    now = dt.datetime(2026, 6, 16, 12, 0, 0, tzinfo=dt.timezone.utc)
    inst = _inst("a", last_active=_iso(120, now), started_at=_iso(9999, now))
    idle = cli._instance_idle_seconds(inst, now)
    assert idle is not None and abs(idle - 120) < 1


def test_idle_seconds_falls_back_to_started_at():
    now = dt.datetime(2026, 6, 16, 12, 0, 0, tzinfo=dt.timezone.utc)
    inst = _inst("a", started_at=_iso(500, now))
    idle = cli._instance_idle_seconds(inst, now)
    assert idle is not None and abs(idle - 500) < 1


def test_idle_seconds_none_without_timestamp():
    now = dt.datetime(2026, 6, 16, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert cli._instance_idle_seconds(_inst("a"), now) is None


def test_select_idle_partitions_by_threshold():
    now = dt.datetime(2026, 6, 16, 12, 0, 0, tzinfo=dt.timezone.utc)
    fresh = _inst("fresh", last_active=_iso(10, now))
    stale = _inst("stale", last_active=_iso(1000, now))
    to_prune, to_keep = cli._select_idle_instances([fresh, stale], 900.0, now)
    assert [i.instance_id for i, _ in to_prune] == ["stale"]
    assert [i.instance_id for i, _ in to_keep] == ["fresh"]


def test_select_idle_keeps_unknown_timestamp():
    now = dt.datetime(2026, 6, 16, 12, 0, 0, tzinfo=dt.timezone.utc)
    unknown = _inst("unknown")  # no timestamp -> never pruned
    to_prune, to_keep = cli._select_idle_instances([unknown], 0.0, now)
    assert to_prune == []
    assert [i.instance_id for i, _ in to_keep] == ["unknown"]
