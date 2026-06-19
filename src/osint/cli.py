from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path

from dotenv import load_dotenv

from osint.agent.graph_view import GraphView
from osint.agent.llm import AgentRunner, create_llm_client
from osint.agent.report import render_report
from osint.core.entities import Entity, EntityType
from osint.core.provenance import Provenance
from osint.orchestrator.authorization import Authorization
from osint.orchestrator.engine import Engine
from osint.util.http import create_http_client
from osint.util.logging import configure_logging


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="osint")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run")
    run_seed = run_parser.add_mutually_exclusive_group(required=True)
    run_seed.add_argument("--domain")
    run_seed.add_argument("--username")
    run_parser.add_argument(
        "--investigation-reason",
        help=(
            "Required for --username. Use only for lawful public-data investigation "
            "(for example due diligence, fraud, or consented checks); you are "
            "responsible for applicable privacy obligations."
        ),
    )
    run_parser.add_argument("--out", default="result.json")
    run_parser.add_argument("--store", choices=["memory", "neo4j"], default="memory")
    run_parser.add_argument("--neo4j-uri")
    run_parser.add_argument("--neo4j-user")
    run_parser.add_argument("--neo4j-password")
    run_parser.add_argument("--max-depth", type=int, default=0)
    run_parser.add_argument("--max-seeds", type=int, default=10)
    run_parser.add_argument("--max-calls", type=int, default=30)
    run_parser.add_argument("--no-cache", action="store_true")
    run_parser.add_argument("--cache-ttl", type=float, default=24 * 60 * 60)
    run_parser.add_argument("--cache-dir", default=".cache/osint")
    run_parser.add_argument(
        "--authorize",
        action="append",
        default=[],
        metavar="TARGET",
        help=(
            "Authorize a domain, IP, or CIDR for pivots. Repeat as needed; "
            "discovered IPs are recorded but not service-enriched unless covered."
        ),
    )

    investigate_parser = subparsers.add_parser("investigate")
    investigate_seed = investigate_parser.add_mutually_exclusive_group(required=True)
    investigate_seed.add_argument("--domain")
    investigate_seed.add_argument("--username")
    investigate_parser.add_argument(
        "--investigation-reason",
        help=(
            "Required for --username. Use only for lawful public-data investigation "
            "(for example due diligence, fraud, or consented checks); you are "
            "responsible for applicable privacy obligations."
        ),
    )
    investigate_parser.add_argument("--store", choices=["memory", "neo4j"], default="memory")
    investigate_parser.add_argument("--neo4j-uri")
    investigate_parser.add_argument("--neo4j-user")
    investigate_parser.add_argument("--neo4j-password")
    investigate_parser.add_argument("--max-depth", type=int, default=1)
    investigate_parser.add_argument("--max-seeds", type=int, default=10)
    investigate_parser.add_argument("--max-calls", type=int, default=30)
    investigate_parser.add_argument("--report", default="investigation.md")
    investigate_parser.add_argument("--model")
    investigate_parser.add_argument("--max-tool-iterations", type=int, default=5)
    investigate_parser.add_argument("--no-cache", action="store_true")
    investigate_parser.add_argument("--cache-ttl", type=float, default=24 * 60 * 60)
    investigate_parser.add_argument("--cache-dir", default=".cache/osint")
    investigate_parser.add_argument(
        "--authorize",
        action="append",
        default=[],
        metavar="TARGET",
        help=(
            "Authorize a domain, IP, or CIDR for pivots. Repeat as needed; "
            "recommendations will still surface authorization required for follow-up work."
        ),
    )

    args = parser.parse_args()
    configure_logging()

    if args.command == "run":
        seed = _seed_from_args(parser, args)
        asyncio.run(
            _run_seed(
                seed,
                Path(args.out),
                args.store,
                args.neo4j_uri,
                args.neo4j_user,
                args.neo4j_password,
                args.max_depth,
                args.max_seeds,
                args.max_calls,
                args.no_cache,
                args.cache_ttl,
                args.cache_dir,
                args.authorize,
                args.investigation_reason,
            )
        )
    if args.command == "investigate":
        seed = _seed_from_args(parser, args)
        asyncio.run(
            _investigate_seed(
                seed,
                args.store,
                args.neo4j_uri,
                args.neo4j_user,
                args.neo4j_password,
                args.max_depth,
                args.max_seeds,
                args.max_calls,
                args.no_cache,
                args.cache_ttl,
                args.cache_dir,
                args.authorize,
                Path(args.report),
                args.model,
                args.max_tool_iterations,
                args.investigation_reason,
            )
        )


async def _run_seed(
    seed: Entity,
    out: Path,
    store_name: str,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    max_depth: int,
    max_seeds: int,
    max_calls: int,
    no_cache: bool,
    cache_ttl: float,
    cache_dir: str,
    authorized_targets: list[str],
    investigation_reason: str | None = None,
) -> None:
    http_client = create_http_client(
        cache_enabled=not no_cache,
        cache_ttl_seconds=cache_ttl,
        cache_dir=cache_dir,
    )
    engine = Engine(
        http_client=http_client,
        config=_engine_config(investigation_reason),
    )
    store = _build_store(store_name, neo4j_uri, neo4j_user, neo4j_password)
    try:
        store, audit_log = await engine.run(
            seed,
            Authorization(in_scope_targets=authorized_targets),
            store=store,
            max_depth=max_depth,
            max_seeds=max_seeds,
            max_calls=max_calls,
        )
        store.snapshot(out)
        _print_summary(store.all_entities(), audit_log, out)
    finally:
        await http_client.aclose()
        close = getattr(store, "close", None)
        if close:
            close()


async def _investigate_seed(
    seed: Entity,
    store_name: str,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
    max_depth: int,
    max_seeds: int,
    max_calls: int,
    no_cache: bool,
    cache_ttl: float,
    cache_dir: str,
    authorized_targets: list[str],
    report_path: Path,
    model: str,
    max_tool_iterations: int,
    investigation_reason: str | None = None,
) -> None:
    http_client = create_http_client(
        cache_enabled=not no_cache,
        cache_ttl_seconds=cache_ttl,
        cache_dir=cache_dir,
    )
    engine = Engine(
        http_client=http_client,
        config=_engine_config(investigation_reason),
    )
    store = _build_store(store_name, neo4j_uri, neo4j_user, neo4j_password)
    try:
        store, _ = await engine.run(
            seed,
            Authorization(in_scope_targets=authorized_targets),
            store=store,
            max_depth=max_depth,
            max_seeds=max_seeds,
            max_calls=max_calls,
        )
        graph = GraphView(store)
        runner = AgentRunner(
            create_llm_client(model=model),
            max_tool_iterations=max_tool_iterations,
        )
        result = await runner.run(graph)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_report(result, graph), encoding="utf-8")
        print(f"Investigation report: {report_path}")
        print(f"Validated findings: {len(result.findings)}")
        print(f"Rejected claims: {len(result.rejected_findings)}")
    finally:
        await http_client.aclose()
        close = getattr(store, "close", None)
        if close:
            close()


def _seed_from_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> Entity:
    if args.domain:
        return _domain_seed(args.domain)
    reason = (args.investigation_reason or "").strip()
    if not reason:
        parser.error(
            "--investigation-reason is required for --username public account-existence checks"
        )
    return _username_seed(args.username, reason)


def _domain_seed(domain: str) -> Entity:
    collected_at = datetime.now(timezone.utc)
    return Entity(
        type=EntityType.Domain,
        value=domain,
        attributes={},
        sources=[
            Provenance(
                connector="cli",
                source="operator",
                query=domain,
                collected_at=collected_at,
                raw_ref={"argv": "--domain"},
            )
        ],
        confidence=1.0,
    )


def _username_seed(username: str, investigation_reason: str) -> Entity:
    collected_at = datetime.now(timezone.utc)
    return Entity(
        type=EntityType.Username,
        value=username,
        attributes={
            "account_status": "search-seed",
            "investigation_reason": investigation_reason,
        },
        sources=[
            Provenance(
                connector="cli",
                source="operator",
                query=username,
                collected_at=collected_at,
                raw_ref={
                    "argv": "--username",
                    "investigation_reason": investigation_reason,
                },
            )
        ],
        confidence=1.0,
        tags={"username-search-seed"},
    )


def _engine_config(investigation_reason: str | None) -> dict[str, str]:
    if not investigation_reason:
        return {}
    return {"investigation_reason": investigation_reason}


def _build_store(
    store_name: str,
    neo4j_uri: str | None,
    neo4j_user: str | None,
    neo4j_password: str | None,
):
    if store_name == "memory":
        return None

    from osint.store.neo4j_store import Neo4jEntityStore

    return Neo4jEntityStore(
        neo4j_uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user or os.environ.get("NEO4J_USER", "neo4j"),
        neo4j_password or os.environ.get("NEO4J_PASSWORD", "change-me"),
    )


def _print_summary(entities: list[Entity], audit_log: list[dict[str, str]], out: Path) -> None:
    counts = Counter(entity.type.value for entity in entities)
    print("OSINT run complete")
    print(f"Snapshot: {out}")
    print(f"Queries issued: {len(audit_log)}")
    print("Entity counts:")
    for type_name, count in sorted(counts.items()):
        print(f"  {type_name}: {count}")

    print("Top entities by confidence:")
    top_entities = sorted(
        entities,
        key=lambda entity: (-entity.confidence, entity.type.value, entity.value),
    )[:10]
    for entity in top_entities:
        print(f"  {entity.confidence:.2f} {entity.type.value} {entity.value}")
