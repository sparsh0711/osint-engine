# OSINT Engine

Passive cyber OSINT graph engine with provenance, Neo4j storage, scoped enrichment, and grounded investigation reports.

## What It Does

OSINT Engine starts from a domain and builds an auditable entity graph from passive sources. It normalizes domains, IP addresses, certificates, and services into deterministic entities, preserves source provenance on every node and relationship, and raises confidence when independent sources corroborate the same fact.

The project is designed for professional cyber investigations where scope control matters. Passive collection is allowed by default; active or scope-expanding enrichment is gated behind explicit authorization.

## Current Capabilities

- Modular connector framework with passive/active safety declarations.
- Passive subdomain and certificate-transparency collection from crt.sh and Cert Spotter.
- Historical hostname discovery from the Wayback Machine CDX API.
- Passive DNS resolution from domains to IP addresses.
- Authorized IPv4 service enrichment through Shodan InternetDB.
- Multi-hop pivoting with depth, seed, and query budgets.
- HTTP resilience layer with disk caching, retry/backoff, and circuit breaking.
- In-memory JSON snapshots and Neo4j graph storage.
- Provider-agnostic LLM agent for grounded triage and Markdown reports.
- Validator rejects ungrounded or contradicted LLM findings before report rendering.

## Safety Model

- No connector bypasses the shared `CollectionContext` HTTP layer.
- Every entity and relationship carries provenance.
- Active or scope-expanding recommendations must surface authorization requirements.
- Discovered IPs are recorded, but service enrichment only runs when the target is authorized.
- Secrets are read from `.env`, which is ignored by Git.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -e ".[test,neo4j]"
copy .env.example .env
```

For Neo4j-backed runs:

```powershell
docker compose up -d
```

Set `NEO4J_PASSWORD` in `.env` to match `docker-compose.yml`.

## Run Passive Collection

Memory store:

```powershell
.\.venv\Scripts\osint.exe run --domain example.com --max-depth 2
```

Neo4j store:

```powershell
.\.venv\Scripts\osint.exe run --domain example.com --max-depth 2 --store neo4j
```

## Run an Investigation Report

Without IP/service enrichment:

```powershell
.\.venv\Scripts\osint.exe investigate --domain example.com --max-depth 2 --store neo4j --report out.md
```

With explicit authorization for an IP or CIDR:

```powershell
.\.venv\Scripts\osint.exe investigate --domain scanme.nmap.org --authorize 45.33.32.156 --max-depth 2 --store neo4j --report out.md
```

## LLM Providers

The agent uses a provider-agnostic client. By default it targets an OpenAI-compatible local endpoint:

```text
OSINT_LLM_PROVIDER=openai_compatible
OSINT_LLM_BASE_URL=http://localhost:11434/v1
OSINT_LLM_MODEL=qwen2.5:3b
```

Hosted OpenAI-compatible endpoints and Anthropic-style providers can be configured with environment variables. API keys belong in `.env` and must not be committed.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The suite uses mocked HTTP for connector tests. Neo4j tests run when Docker/Neo4j is available and skip otherwise.

## Architecture

See [DESIGN.md](DESIGN.md) for the full design specification, data model, connector contract, confidence merge rules, and phased roadmap.

## Status

Implemented through Phase 8:

- Core engine and deterministic graph model.
- Passive connectors: crt.sh, Wayback, DNS, Cert Spotter.
- Authorized InternetDB service enrichment.
- Resilience layer.
- Neo4j storage.
- Grounded LLM reporting.
- Redundant CT source hardening and Neo4j relationship write fix.
