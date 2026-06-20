from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from osint.connectors.context import CollectionContext
from osint.connectors.usernames import UsernamesConnector
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType
from osint.store.memory import MemoryEntityStore


async def test_usernames_exists_emits_username_person_and_edge(
    respx_mock,
    tmp_path,
) -> None:
    dataset = _dataset(
        tmp_path,
        [
            _site("ExampleSite", "https://example.test/{account}", "exists-marker"),
            _site("MissingSite", "https://missing.test/{account}", "exists-marker"),
        ],
    )
    respx_mock.get("https://example.test/alice").respond(
        200,
        text="<html>exists-marker profile body that must not be stored</html>",
    )
    respx_mock.get("https://missing.test/alice").respond(
        404,
        text="not found",
    )
    ctx = CollectionContext(
        http=PassthroughHttpClient(),
        logger=RecordingLogger(),
        config={"investigation_reason": "consented test"},
    )

    findings = [
        finding
        async for finding in UsernamesConnector(dataset).collect(_seed("alice"), ctx)
    ]

    usernames = [
        entity
        for finding in findings
        for entity in finding.entities
        if entity.type == EntityType.Username
    ]
    people = [
        entity
        for finding in findings
        for entity in finding.entities
        if entity.type == EntityType.Person
    ]
    relationships = [
        relationship for finding in findings for relationship in finding.relationships
    ]

    assert len(usernames) == 1
    assert usernames[0].value == "ExampleSite:alice"
    assert usernames[0].confidence == 0.5
    assert usernames[0].attributes == {
        "platform": "ExampleSite",
        "profile_url": "https://example.test/alice",
        "account_status": "exists",
    }
    assert "unverified-lead" in usernames[0].tags
    assert people
    assert people[0].type == EntityType.Person
    assert any(
        relationship.type == RelationType.ASSOCIATED_WITH
        and relationship.src_id == usernames[0].id
        and relationship.dst_id == people[0].id
        for relationship in relationships
    )
    assert all(entity.sources for entity in [*usernames, *people])
    assert all(relationship.sources for relationship in relationships)


async def test_usernames_indeterminate_and_failures_do_not_mark_exists(
    respx_mock,
    tmp_path,
) -> None:
    dataset = _dataset(
        tmp_path,
        [
            _site("Challenge", "https://challenge.test/{account}", "exists-marker"),
            _site("Failure", "https://failure.test/{account}", "exists-marker"),
        ],
    )
    respx_mock.get("https://challenge.test/alice").respond(403, text="challenge")
    respx_mock.get("https://failure.test/alice").mock(
        side_effect=httpx.ConnectError("network down")
    )
    logger = RecordingLogger()
    ctx = CollectionContext(http=PassthroughHttpClient(), logger=logger)

    findings = [
        finding
        async for finding in UsernamesConnector(dataset).collect(_seed("alice"), ctx)
    ]

    assert findings == []
    assert any(event == "username_site_indeterminate" for _level, event, _kw in logger.events)
    assert any(
        event == "username_site_check_incomplete" for _level, event, _kw in logger.events
    )


async def test_usernames_http_200_not_found_page_does_not_mark_exists(
    respx_mock,
    tmp_path,
) -> None:
    dataset = _dataset(
        tmp_path,
        [_site("SoftMissing", "https://softmissing.test/{account}", "profile exists")],
    )
    respx_mock.get("https://softmissing.test/alice").respond(
        200,
        text="<html>not found</html>",
    )
    ctx = CollectionContext(http=PassthroughHttpClient(), logger=RecordingLogger())

    findings = [
        finding
        async for finding in UsernamesConnector(dataset).collect(_seed("alice"), ctx)
    ]

    assert findings == []


async def test_usernames_single_site_hit_stays_low_confidence_with_operator_intent(
    respx_mock,
    tmp_path,
) -> None:
    dataset = _dataset(
        tmp_path,
        [_site("ExampleSite", "https://example.test/{account}", "exists-marker")],
    )
    respx_mock.get("https://example.test/alice").respond(
        200,
        text="exists-marker",
    )
    ctx = CollectionContext(
        http=PassthroughHttpClient(),
        logger=RecordingLogger(),
        config={"investigation_reason": "consented check"},
    )
    store = MemoryEntityStore()

    findings = [
        finding
        async for finding in UsernamesConnector(dataset).collect(_seed("alice"), ctx)
    ]
    for finding in findings:
        for entity in finding.entities:
            store.upsert_entity(entity)
        for relationship in finding.relationships:
            store.upsert_relationship(relationship)

    person = next(
        entity for entity in store.all_entities() if entity.type == EntityType.Person
    )
    username = next(
        entity for entity in store.all_entities() if entity.type == EntityType.Username
    )

    assert person.confidence == pytest.approx(0.5)
    assert username.confidence == pytest.approx(0.5)
    assert {source.source for source in person.sources} == {"whatsmyname"}
    assert any(
        source.raw_ref.get("provenance_role") == "operator-intent-metadata"
        for source in person.sources
    )


async def test_usernames_concurrency_is_bounded(tmp_path) -> None:
    dataset = _dataset(
        tmp_path,
        [
            _site(f"Site{index}", f"https://site{index}.test/{{account}}", "exists")
            for index in range(6)
        ],
    )
    http = CountingHttpClient()
    ctx = CollectionContext(http=http, logger=RecordingLogger())

    findings = [
        finding
        async for finding in UsernamesConnector(
            dataset,
            max_concurrency=2,
        ).collect(_seed("alice"), ctx)
    ]

    assert len(findings) == 6
    assert http.max_active == 2


def _dataset(tmp_path: Path, sites: list[dict]) -> Path:
    path = tmp_path / "wmn-data.json"
    path.write_text(json.dumps({"sites": sites}), encoding="utf-8")
    return path


def _site(name: str, url: str, expected: str) -> dict:
    return {
        "name": name,
        "uri_check": url,
        "e_code": 200,
        "e_string": expected,
        "m_code": 404,
        "m_string": "not found",
        "known": ["alice"],
        "cat": "test",
    }


def _seed(username: str) -> Entity:
    return Entity(
        type=EntityType.Username,
        value=username,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=username,
                raw_ref={"seed": username},
            )
        ],
        confidence=1.0,
    )


class PassthroughHttpClient:
    async def get(self, url: str, **kwargs):
        async with httpx.AsyncClient() as client:
            return await client.get(url, **kwargs)


class CountingHttpClient:
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0

    async def get(self, url: str, **kwargs):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        return httpx.Response(200, text="exists", request=httpx.Request("GET", url))


class RecordingLogger:
    def __init__(self) -> None:
        self.events = []

    def info(self, event: str, **kwargs) -> None:
        self.events.append(("info", event, kwargs))

    def warning(self, event: str, **kwargs) -> None:
        self.events.append(("warning", event, kwargs))
