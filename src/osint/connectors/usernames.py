from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from osint.connectors.base import CollectionMode, Connector, register
from osint.connectors.context import CollectionContext
from osint.core.entities import Entity, EntityType
from osint.core.findings import Finding
from osint.core.provenance import Provenance
from osint.core.relationships import RelationType, Relationship


@dataclass(frozen=True)
class UsernameSite:
    name: str
    url: str
    expected_code: int
    expected_string: str
    missing_code: int
    missing_string: str
    category: str | None = None
    headers: dict[str, str] | None = None


@register
class UsernamesConnector(Connector):
    name = "usernames"
    source = "whatsmyname"
    description = "Public account-existence checks by username (WMN dataset)"
    mode = CollectionMode.PASSIVE
    accepts = {EntityType.Username}
    produces = {EntityType.Username, EntityType.Person}
    requires_api_key = False
    base_confidence = 0.5

    def __init__(
        self,
        dataset_path: str | Path | None = None,
        *,
        max_concurrency: int = 8,
        max_sites: int | None = None,
    ) -> None:
        self.dataset_path = Path(dataset_path) if dataset_path is not None else None
        self.max_concurrency = max(1, max_concurrency)
        self.max_sites = max_sites

    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        username = str(seed.value).strip()
        if not username:
            return

        sites = self._load_sites()
        if self.max_sites is not None:
            sites = sites[: self.max_sites]

        person = self._person_entity(username, seed, ctx.config)
        semaphore = asyncio.Semaphore(self.max_concurrency)
        tasks = [
            asyncio.create_task(self._check_site(site, username, person, semaphore, ctx))
            for site in sites
        ]
        try:
            for task in asyncio.as_completed(tasks):
                finding = await task
                if finding is not None:
                    yield finding
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    def _load_sites(self) -> list[UsernameSite]:
        if self.dataset_path is not None:
            payload = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        else:
            data = resources.files("osint.data").joinpath("wmn-data.json")
            payload = json.loads(data.read_text(encoding="utf-8"))

        raw_sites = payload.get("sites", []) if isinstance(payload, dict) else []
        sites: list[UsernameSite] = []
        for raw in raw_sites:
            site = _site_from_raw(raw)
            if site is not None:
                sites.append(site)
        return sites

    async def _check_site(
        self,
        site: UsernameSite,
        username: str,
        person: Entity,
        semaphore: asyncio.Semaphore,
        ctx: CollectionContext,
    ) -> Finding | None:
        url = site.url.replace("{account}", quote(username, safe=""))
        try:
            async with semaphore:
                response = await ctx.http.get(url, headers=site.headers)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            if ctx.logger:
                ctx.logger.info(
                    "username_site_check_incomplete",
                    platform=site.name,
                    error=str(exc),
                )
            return None

        status = _status_for_response(response, site)
        if status != "exists":
            if ctx.logger and status == "indeterminate":
                ctx.logger.info("username_site_indeterminate", platform=site.name)
            return None

        collected_at = datetime.now(timezone.utc)
        provenance = Provenance(
            connector=self.name,
            source=self.source,
            query=url,
            collected_at=collected_at,
            raw_ref={
                "platform": site.name,
                "category": site.category,
                "account_status": "exists",
            },
        )
        username_entity = Entity(
            type=EntityType.Username,
            value=f"{site.name}:{username}",
            attributes={
                "platform": site.name,
                "profile_url": url,
                "account_status": "exists",
            },
            sources=[provenance],
            confidence=self.base_confidence,
            tags={"unverified-lead"},
        )
        relationship = Relationship(
            type=RelationType.ASSOCIATED_WITH,
            src_id=username_entity.id,
            dst_id=person.id,
            sources=[provenance],
            confidence=self.base_confidence,
        )
        person_with_source = person.model_copy(deep=True)
        person_with_source.sources = [*person.sources, provenance]
        return Finding(
            entities=[person_with_source, username_entity],
            relationships=[relationship],
        )

    def _person_entity(
        self,
        username: str,
        seed: Entity,
        config: dict[str, Any],
    ) -> Entity:
        reason = str(config.get("investigation_reason") or "")
        provenance = Provenance(
            connector=self.name,
            source="operator-intent",
            query=username,
            raw_ref={
                "seed_id": seed.id,
                "investigation_reason": reason,
            },
        )
        return Entity(
            type=EntityType.Person,
            value=f"username-search:{username}",
            attributes={
                "name": None,
                "aliases": [],
                "subject_type": "username-search",
                "unverified": True,
            },
            sources=[provenance],
            confidence=self.base_confidence,
            tags={"username-search-subject", "unverified-lead"},
        )


def _site_from_raw(raw: Any) -> UsernameSite | None:
    if not isinstance(raw, dict):
        return None
    if raw.get("post_body") is not None:
        return None
    name = raw.get("name")
    url = raw.get("uri_check")
    if not isinstance(name, str) or not isinstance(url, str):
        return None
    if "{account}" not in url:
        return None
    try:
        expected_code = int(raw.get("e_code"))
        missing_code = int(raw.get("m_code"))
    except (TypeError, ValueError):
        return None
    expected_string = raw.get("e_string")
    missing_string = raw.get("m_string")
    if not isinstance(expected_string, str) or not isinstance(missing_string, str):
        return None
    headers = raw.get("headers")
    if not isinstance(headers, dict):
        headers = None
    else:
        headers = {
            str(key): str(value)
            for key, value in headers.items()
            if isinstance(key, str) and isinstance(value, str)
        }
    category = raw.get("cat")
    return UsernameSite(
        name=name,
        url=url,
        expected_code=expected_code,
        expected_string=expected_string,
        missing_code=missing_code,
        missing_string=missing_string,
        category=category if isinstance(category, str) else None,
        headers=headers,
    )


def _status_for_response(response: httpx.Response, site: UsernameSite) -> str:
    if response.status_code in {401, 403, 429, 503}:
        return "indeterminate"
    text = response.text
    if response.status_code == site.missing_code:
        return "not_found"
    if site.missing_string and site.missing_string in text:
        return "not_found"
    if response.status_code == site.expected_code and site.expected_string in text:
        return "exists"
    return "indeterminate"
