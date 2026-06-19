from __future__ import annotations

import sys

import pytest

from osint import cli
from osint.core.entities import EntityType


def test_username_investigation_requires_reason(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["osint", "investigate", "--username", "alice"],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_username_investigation_reason_is_recorded(monkeypatch) -> None:
    captured = {}

    async def fake_investigate(
        seed,
        store_name,
        neo4j_uri,
        neo4j_user,
        neo4j_password,
        max_depth,
        max_seeds,
        max_calls,
        no_cache,
        cache_ttl,
        cache_dir,
        authorized_targets,
        report_path,
        model,
        max_tool_iterations,
        investigation_reason=None,
    ):
        captured["seed"] = seed
        captured["investigation_reason"] = investigation_reason

    monkeypatch.setattr(cli, "_investigate_seed", fake_investigate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "osint",
            "investigate",
            "--username",
            "alice",
            "--investigation-reason",
            "consented check",
        ],
    )

    cli.main()

    seed = captured["seed"]
    assert seed.type == EntityType.Username
    assert captured["investigation_reason"] == "consented check"
    assert seed.sources[0].raw_ref["investigation_reason"] == "consented check"
