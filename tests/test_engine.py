from __future__ import annotations

from collections.abc import AsyncIterator

from osint.connectors.base import CollectionMode, Connector
from osint.connectors.crtsh import CrtShConnector
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine
from osint.util.http import create_http_client
from osint.util.ratelimit import AsyncTokenBucketLimiter


async def test_engine_runs_crtsh_end_to_end_with_mocked_http(respx_mock) -> None:
    respx_mock.get("https://crt.sh/?q=%25.example.com&output=json").respond(
        200,
        json=[
            {
                "id": 1,
                "serial_number": "abc",
                "issuer_name": "Test CA",
                "common_name": "www.example.com",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "name_value": "www.example.com\napi.example.com",
            }
        ],
    )
    http = create_http_client(AsyncTokenBucketLimiter(default_rate=100, capacity=100))
    engine = Engine(connectors=[CrtShConnector()], http_client=http)

    store, audit_log = await engine.run(_seed("example.com"), Authorization())
    await http.aclose()

    assert len(audit_log) == 1
    assert audit_log[0]["connector"] == "crtsh"
    assert any(entity.value == "api.example.com" for entity in store.all_entities())
    assert store.all_relationships()


async def test_active_connector_refused_outside_authorization() -> None:
    connector = DummyActiveConnector()
    engine = Engine(connectors=[connector])

    await engine.run(_seed("outside.example"), Authorization(in_scope_targets=["example.com"]))

    assert connector.ran is False


async def test_active_connector_runs_inside_authorization() -> None:
    connector = DummyActiveConnector()
    engine = Engine(connectors=[connector])

    await engine.run(_seed("api.example.com"), Authorization(in_scope_targets=["example.com"]))

    assert connector.ran is True


class DummyActiveConnector(Connector):
    name = "dummy-active"
    source = "dummy"
    description = "Dummy active connector for authorization tests"
    mode = CollectionMode.ACTIVE
    accepts = {EntityType.Domain}
    produces = {EntityType.Domain}
    requires_api_key = False
    base_confidence = 0.5

    def __init__(self) -> None:
        self.ran = False

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        self.ran = True
        if False:
            yield Finding()


def _seed(domain: str) -> Entity:
    return Entity(
        type=EntityType.Domain,
        value=domain,
        attributes={},
        sources=[
            Provenance(
                connector="test",
                source="test",
                query=domain,
                raw_ref={"seed": domain},
            )
        ],
        confidence=1.0,
    )
