# OSINT Engine — Design Specification

> Reference document for all contributors and coding agents (Codex, Claude, Gemini, Copilot).
> This file defines the **what and why**. Build briefs (e.g. `PHASE1_BRIEF.md`) define the **how and now**.
> When in doubt, this document wins. If you need to deviate, update this document in the same change.

---

## 1. Purpose & scope

A modular **OSINT collection engine** for cyber-focused investigations (infrastructure, exposure, identity), built for real professional use. It takes a seed (domain, IP, email, etc.), fans out across pluggable **connectors**, normalizes everything into a typed **entity graph** with full provenance, and produces a reproducible, auditable investigation result.

A later phase adds an **agent layer** that orchestrates the engine's connectors for pivoting and report-writing. The agent never produces intelligence on its own — it only calls connectors and synthesizes their grounded output.

**Primary domain:** cyber (infrastructure & exposure). General-purpose entities (person, org) are first-class in the schema but secondary in connector coverage.

---

## 2. Non-negotiable principles

These are architectural invariants, not guidelines. Every connector and every result must honor them.

1. **Passive by default, active only with authorization.** See §7. This is a hard gate enforced by the orchestrator, not a convention.
2. **Every data point carries provenance.** No entity or relationship exists without at least one source record (which connector, which source, when, and a reference to the raw artifact).
3. **Every data point carries a confidence score** (0.0–1.0). Corroboration across independent sources raises it.
4. **Reproducibility & audit.** Every run logs every query made, in order, with timestamps. Re-running the same seed against the same sources yields the same entity IDs (deterministic identity).
5. **Connectors are isolated and declarative.** A connector declares what it accepts, what it produces, and whether it is passive or active. Adding a source = dropping in one module. No connector reaches into engine internals.
6. **The engine never silently violates rate limits or ToS.** Rate limiting and polite backoff are mandatory and centrally enforced.

---

## 3. Architecture layers

Phase 4 generalizes the orchestrator into a frontier-based multi-hop loop. It still dispatches applicable connectors concurrently per seed, but newly discovered entities are only enqueued for later hops when they pass the pivot policy and the run's depth/budget limits.

```
                 ┌─────────────────────────────────────────────┐
   (Phase 5)     │              Agent layer (LLM)               │
                 │   plans pivots · prioritizes · writes report │
                 └───────────────────────┬─────────────────────┘
                                          │ calls connectors as tools
                 ┌────────────────────────▼────────────────────┐
   Orchestrator  │  run loop · seed queue · passive/active gate │
                 │  dedup/merge · confidence scoring · audit log│
                 └───┬──────────────────┬───────────────────┬───┘
                     │                  │                   │
            ┌────────▼──────┐  ┌────────▼───────┐  ┌────────▼───────┐
 Connectors │ crt.sh        │  │ shodan         │  │ ...            │
 (plugins)  │ (passive)     │  │ (passive)      │  │                │
            └────────┬──────┘  └────────┬───────┘  └────────┬───────┘
                     │ Findings (entities + relationships + provenance)
                 ┌───▼──────────────────────────────────────────┐
 Normalization   │  entity resolution · deterministic IDs · merge│
                 └───┬──────────────────────────────────────────┘
                 ┌───▼──────────────────────────────────────────┐
 Storage         │  EntityStore interface                        │
                 │  Phase 1: in-memory + JSON   Phase 2: Neo4j    │
                 └───┬──────────────────────────────────────────┘
                 ┌───▼──────────────────────────────────────────┐
 Presentation    │  report (sources + confidence) · link graph   │
                 └──────────────────────────────────────────────┘
```

---

## 4. Entity model

Entities are the nodes of the graph. Every entity shares a common envelope; type-specific fields live in `attributes`.

### Common envelope (all entities)

| Field         | Type                  | Notes |
|---------------|-----------------------|-------|
| `id`          | `str`                 | Deterministic. Derived from `(type, canonical_value)`. See §6. |
| `type`        | `EntityType`          | Enum. |
| `value`       | `str`                 | Canonical, normalized value (lowercased domain, compressed IPv6, etc.). |
| `attributes`  | `dict`                | Type-specific structured fields. |
| `sources`     | `list[Provenance]`    | One per discovery. Never empty. |
| `confidence`  | `float`               | 0.0–1.0. Recomputed on merge. |
| `first_seen`  | `datetime`            | Earliest collection time. |
| `last_seen`   | `datetime`            | Latest collection time. |
| `tags`        | `set[str]`            | Free-form labels (e.g. `wildcard`, `expired`). |

### Entity types (cyber-first)

- **Domain** — `attributes`: `registered_domain`, `tld`, `is_wildcard`.
- **IPAddress** — `attributes`: `version` (4/6), `is_private`.
- **Certificate** — `attributes`: `sha256`, `serial`, `issuer`, `subject`, `not_before`, `not_after`, `sans` (list).
- **Service** — a host:port observation. `attributes`: `ip`, `port`, `protocol`, `product`, `banner`. (Populated by scan-data sources like Shodan in Phase 3.)
- **ASN** — `attributes`: `number`, `name`, `org`.
- **Netblock** — `attributes`: `cidr`, `asn`.
- **Email** — `attributes`: `local`, `domain`.
- **Username** — `attributes`: `platform` (nullable).
- **URL** — `attributes`: `scheme`, `host`, `path`.
- **Person** — secondary; `attributes`: `name`, `aliases`.
- **Organization** — secondary; `attributes`: `name`, `legal_id`.

> Adding an entity type = extend the `EntityType` enum and document its `attributes` here. No other layer should hardcode type knowledge except entity-ID derivation (§6).

Phase 4 begins producing `IPAddress` entities from passive DNS resolution; the schema type pre-existed and did not change.

---

## 5. Relationship model

Relationships are typed, directed edges. They carry their **own** provenance and confidence (the same envelope minus `value`/`attributes`).

| Relation        | From → To                | Meaning |
|-----------------|--------------------------|---------|
| `HAS_SUBDOMAIN` | Domain → Domain          | Registered domain to discovered subdomain. |
| `RESOLVES_TO`   | Domain → IPAddress       | DNS resolution observation. |
| `SECURES`       | Certificate → Domain     | Cert SAN/CN covers this domain. |
| `ANNOUNCES`     | ASN → Netblock           | ASN announces this prefix. |
| `CONTAINS`      | Netblock → IPAddress     | IP falls within prefix. |
| `HOSTS`         | IPAddress → Service      | Observed service on host. |
| `ASSOCIATED_WITH` | Email/Username → Person | Identity linkage (lower default confidence). |

Edge envelope: `{ id, type, src_id, dst_id, sources, confidence, first_seen, last_seen }`. Edge `id` is deterministic from `(type, src_id, dst_id)`.

Phase 4 begins producing `RESOLVES_TO` relationships from passive DNS resolution; the relationship type pre-existed and did not change.

---

## 6. Identity & deduplication

- **Deterministic IDs.** `id = sha1(f"{type}:{canonical_value}")[:16]`. Canonicalization rules per type live in `core/ids.py` (lowercase + strip trailing dot for domains; `ipaddress` module normalization for IPs; `sha256` for certs).
- **Merge on collision.** When a connector yields an entity whose ID already exists, the store **merges**: unions `sources`, unions `tags`, extends `first_seen`/`last_seen`, deep-merges `attributes` (new non-null fields win only if previously absent; conflicts are recorded under `attributes["_conflicts"]`).
- **Confidence on merge.** Base confidence is per-connector (declared on the connector). On merge, confidence rises with independent corroboration:
  `confidence = 1 - Π(1 - c_i)` over distinct **source names** (not distinct findings). Capped at 0.99. This is the noisy-OR rule: two independent 0.7 sources → 0.91.

---

## 7. The passive / active boundary

The single most important professional control in the system.

- Every connector declares `mode: CollectionMode` ∈ {`PASSIVE`, `ACTIVE`}.
  - **PASSIVE** = querying third-party databases that already hold the data (certificate transparency, passive DNS, Shodan's existing scans, breach indexes). No packets to the target.
  - **ACTIVE** = touching the target's own infrastructure (port scans, vuln scans, directory brute-forcing, direct probing).
- A run carries an `Authorization` object describing the in-scope targets the operator is authorized to actively engage.
- **The orchestrator refuses to dispatch an ACTIVE connector against a seed unless that seed's target is covered by the run's `Authorization`.** Refusals are logged. Unauthorized active collection is illegal in many jurisdictions regardless of intent — this gate exists so the engine cannot do it by accident.
- Phase 1 ships **zero** active connectors. The gate is built and tested anyway (with a dummy active connector in tests) so the boundary exists before any active capability does.

---

## 8. Connector contract

```python
class CollectionMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"

class Connector(ABC):
    name: str                      # unique, e.g. "crtsh"
    source: str                    # human source label, e.g. "crt.sh"
    description: str
    mode: CollectionMode
    accepts: set[EntityType]       # seed types it can act on
    produces: set[EntityType]      # entity types it may yield
    requires_api_key: bool = False
    base_confidence: float = 0.6   # per-source prior

    @abstractmethod
    async def collect(
        self, seed: Entity, ctx: CollectionContext
    ) -> AsyncIterator[Finding]:
        """Yield Findings derived from `seed`. Must not mutate `seed`.
        Must route all network I/O through `ctx` (rate-limited, cached)."""
```

- **`CollectionContext`** provides everything a connector may touch: a rate-limited `httpx.AsyncClient`, the cache, config/secrets, a structured logger, and the run `Authorization`. Connectors get nothing else — no direct store access, no global state.
- **`Finding`** = `{ entities: list[Entity], relationships: list[Relationship] }` produced from one logical observation, each element already populated with a `Provenance` record stamped with the connector's `name`, `source`, query, timestamp, and a `raw_ref` (pointer to the stored raw artifact).
- Connectors construct `Domain` entities via the shared `build_domain_entity` helper so the §4 domain rules cannot drift between connectors.
- Connectors are **registered** via decorator/entry-point into a `REGISTRY` keyed by `name`; the orchestrator selects applicable connectors by matching `seed.type ∈ connector.accepts`.

---

## 9. Tech stack

| Concern            | Choice                                  | Why |
|--------------------|-----------------------------------------|-----|
| Language           | Python 3.11+                            | Dominant in security tooling. |
| Models/validation  | `pydantic` v2                           | Typed entities, free serialization/validation. |
| Async I/O          | `asyncio` + `httpx`                     | Concurrent collection. |
| Rate limiting      | custom token-bucket per source          | Central, ToS-respecting. |
| HTTP resilience    | central `ctx.http` wrapper              | Disk cache, retry/backoff, and per-host circuit breaking without connector logic. |
| Disk cache         | JSON files under `.cache/osint/`        | Cross-run reuse for slow-moving passive-source responses. |
| Logging            | `structlog`                             | Structured audit trail. |
| Storage (P1-P2)    | in-memory + JSON snapshot               | Zero infra; testable. |
| Storage (P3)       | Neo4j                                   | Native graph queries & link analysis. |
| API (future)       | FastAPI                                 | Backend for UI. |
| Tests              | `pytest`, `pytest-asyncio`, `respx`     | HTTP mocked; **no live network in CI**. |
| Agent (P6)         | Claude tool-use                         | Orchestrates connectors as tools. |

### Neo4j graph model (Phase 3)

Entities persist as nodes with labels `:Entity` and the entity type label, such as `:Domain` or `:Certificate`, under a uniqueness constraint on `Entity.id`. Native properties store `id`, `value`, `confidence`, `first_seen`, `last_seen`, and `tags`; nested fields are losslessly serialized as `attributes_json`, `sources_json`, and `source_confidences_json`.

Relationships persist as typed Neo4j relationships (`:SECURES`, `:HAS_SUBDOMAIN`, etc.) with `id`, `confidence`, `first_seen`, `last_seen`, `sources_json`, and `source_confidences_json`. Relationship types are selected only from the `RelationType` enum. The Neo4j store uses read-modify-write and the shared store merge functions; Cypher only reads and writes merged properties. Modeling provenance as separate `:Source` nodes is deferred until a later phase.

Phase 3 adds a minimal `Engine.run(..., store=None)` injection hook because the Phase 1 engine always constructed `MemoryEntityStore` internally. The hook preserves the existing default while allowing Neo4j to receive individual findings during collection, which is required to persist the exact per-source confidence map.

### Multi-hop pivoting (Phase 4)

Multi-hop pivoting is opt-in: `max_depth=0` processes only the initial seed, preserving the Phase 1-3 single-hop behavior. Runs also carry conservative default budgets (`max_seeds=10`, `max_calls=30`); a budget stop is recorded in the audit log.

Recording and pivoting are separate controls. Every discovered entity and relationship is stored with provenance, but a discovered entity becomes a later seed only if the current depth is below `max_depth`, the entity has not already been visited, at least one registered connector accepts its type, and the pivot policy allows it. Domains pivot only when `attributes["under_seed"] is True`; `co-san` and external domains are terminal. IP addresses pivot only when the run authorization covers them. Other entity types are terminal in Phase 4.

The passive/active gate is enforced per hop before dispatch. Unauthorized active connectors are refused and recorded in the audit log; Phase 4 still ships no active connectors.

### HTTP resilience (Phase 5)

All connector HTTP traffic still flows through `CollectionContext.http`; connectors keep the same `.get()` interface and do not implement resilience themselves.

The disk cache is keyed by `sha256(full_request_url)` and stores the URL, status code, headers, body, and fetch timestamp. Fresh entries are served without touching the network. The default TTL is 24 hours and is configurable per run. Only definitive responses are cached: 2xx and 404. Transient failures such as 429, 5xx, and timeouts are never cached.

The retry policy retries 429, 500, 502, 503, 504, connection errors, and read/connect timeouts. Other 4xx responses, including 400, 401, 403, and 404, return immediately. Backoff is exponential with jitter, a maximum delay cap, and `Retry-After` support on 429 and 503 responses.

The circuit breaker is per host and per run. After repeated post-retry failures, the host circuit opens and later requests fail fast without network I/O. After a cooldown, the breaker allows one half-open trial; success closes the circuit and resets the failure count. Circuit open/close events are logged for audit visibility.

Per-host configuration can override defaults such as timeout and retry count without changing connector modules. DNS resolution does not use `ctx.http`, so DNS retry/caching is deferred. `Retry-After`-aware adaptive rate limiting is also deferred.

---

## 10. Phased roadmap

1. **Core engine + plugin interface + crt.sh.** Orchestration loop, entity/relationship schema, deterministic IDs, in-memory/JSON store, passive/active gate, one passive connector (crt.sh). Proven end-to-end on a domain. *(see `PHASE1_BRIEF.md`)*
2. **Second passive connector + cross-source confidence.** Add Wayback Machine CDX as an independent passive source and prove noisy-OR confidence across overlapping `Domain` entities.
3. **Entity resolution + Neo4j.** Swap store to Neo4j behind the same interface; richer merge/link analysis.
4. **Multi-hop pivoting + DNS resolution.** Frontier-based pivoting with depth/budget controls and passive DNS resolution from Domain to IPAddress.
5. **Resilience layer.** Disk caching, retry/backoff, per-host circuit breaking, and per-host HTTP configuration behind `CollectionContext.http`.
6. **Breadth.** InternetDB first, then Shodan, Censys, passive DNS, Amass/Subfinder wrappers, HaveIBeenPwned, GitHub dorking, and the first gated active connector.
7. **Reporting + visualization.** Investigation report with per-finding sources & confidence; link-graph view.
8. **Agent layer.** LLM planner that pivots across connectors and writes the narrative report. Engine remains the source of truth.

---

## 11. Repo layout

```
osint-engine/
├── DESIGN.md                 # this file
├── PHASE1_BRIEF.md           # current build brief for Codex
├── README.md
├── pyproject.toml
├── .env.example
├── src/osint/
│   ├── core/                 # entities, relationships, provenance, findings, ids
│   ├── connectors/           # base (ABC + registry), context, crtsh
│   ├── store/                # base (ABC), memory
│   ├── orchestrator/         # engine, authorization
│   ├── util/                 # ratelimit, http, logging
│   └── cli.py
└── tests/                    # mocked-HTTP unit tests, no live network
```

---

## 12. Coding-agent rules

- Work against this spec. Do not invent schema or connector behavior not described here; if a gap exists, propose an edit to this file.
- One driver per file at a time. Do not let two agents refactor the same module in parallel.
- No connector may bypass `CollectionContext` for I/O.
- No feature may emit an entity/relationship without provenance.
- Tests must not hit the live network.
