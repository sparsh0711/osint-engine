from __future__ import annotations

from osint.core.entities import EntityType

from tests.test_usernames import (
    PassthroughHttpClient,
    RecordingLogger,
    _dataset,
    _seed,
    _site,
)
from osint.connectors.context import CollectionContext
from osint.connectors.usernames import UsernamesConnector


async def test_username_connector_does_not_store_profile_body_or_personal_details(
    respx_mock,
    tmp_path,
) -> None:
    dataset = _dataset(
        tmp_path,
        [_site("ExampleSite", "https://example.test/{account}", "exists-marker")],
    )
    respx_mock.get("https://example.test/alice").respond(
        200,
        text=(
            "exists-marker real name Alice Example phone 555-0100 "
            "address 123 Test Street date of birth 2000-01-01"
        ),
    )
    ctx = CollectionContext(http=PassthroughHttpClient(), logger=RecordingLogger())

    findings = [
        finding
        async for finding in UsernamesConnector(dataset).collect(_seed("alice"), ctx)
    ]

    username = next(
        entity
        for finding in findings
        for entity in finding.entities
        if entity.type == EntityType.Username
    )
    assert set(username.attributes) == {
        "platform",
        "profile_url",
        "account_status",
    }
    serialized = username.model_dump_json()
    assert "Alice Example" not in serialized
    assert "555-0100" not in serialized
    assert "123 Test Street" not in serialized
    assert "2000-01-01" not in serialized

    person = next(
        entity
        for finding in findings
        for entity in finding.entities
        if entity.type == EntityType.Person
    )
    assert person.attributes["aliases"] == []
