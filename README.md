# OSINT Engine

OSINT Engine is a scoped cyber-OSINT investigation engine that builds an auditable graph from passive public sources, stores it in memory or Neo4j, and can generate grounded investigation reports through an injectable LLM client.

The project is designed around one core rule: collect useful intelligence without losing authorization control. Passive identification data can be gathered broadly, while exposure-style enrichment such as service and port data remains gated behind explicit authorization.

## What It Does

Starting from a domain or username, OSINT Engine collects normalized entities and relationships with source provenance, confidence scores, and deterministic IDs. It can pivot across domains, IP addresses, ASNs, netblocks, services, usernames, certificates, URLs, and vulnerabilities while keeping every claim traceable to source data.

The agent layer can reason over the collected graph, but final reports are validated before rendering. Ungrounded, contradicted, or unsafe model claims are rejected instead of being shown as findings.

## Current Capabilities

- Deterministic entity model with provenance, confidence merging, and stable IDs.
- Passive subdomain discovery from crt.sh, Cert Spotter, and Wayback Machine.
- Passive DNS resolution from domains to IP addresses.
- ASN and netblock enrichment through Team Cymru DNS.
- Authorized service enrichment through Shodan InternetDB.
- First-class Vulnerability entities and `HAS_VULNERABILITY` relationships.
- CVE enrichment through Shodan CVEDB, including CVSS, EPSS, KEV, and severity.
- Neo4j graph storage with queryable Vulnerability properties: `cvss`, `epss`, `kev`, and `severity`.
- Multi-hop pivoting with depth, seed, and call budgets.
- HTTP resilience layer with caching, retry/backoff, and circuit breaking.
- Username existence checks via a vendored WhatsMyName dataset.
- Provider-agnostic LLM client for local Ollama/OpenAI-compatible endpoints or hosted providers.
- Grounded report validator that rejects fabricated or unsupported findings.

## Safety Model

- Passive collection is allowed by default.
- Exposure enrichment is gated behind `--authorize`.
- ASN, netblock, and CVE metadata are identification enrichment and can run on discovered IPs or CVEs.
- InternetDB service enrichment remains authorization-gated.
- Username checks are account-existence only: no profile scraping, login attempts, or personal data collection.
- Same-handle username results are treated as unverified leads, not proof of a single person.
- Agent findings must cite graph entities and must pass validation before report rendering.
- Secrets are read from `.env`, which is ignored by Git.

See [SECURITY.md](SECURITY.md) for the authorized-use policy.

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

Set `NEO4J_PASSWORD` in `.env` to match the password used by `docker-compose.yml`.

## Configuration

Local-only values belong in `.env`:

```text
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=change-me

OSINT_LLM_PROVIDER=openai_compatible
OSINT_LLM_BASE_URL=http://localhost:11434/v1
OSINT_LLM_MODEL=qwen2.5:3b
OSINT_LLM_API_KEY=
OSINT_LLM_TIMEOUT=300
```

Do not commit `.env` or API keys. The repository includes `.env.example` as a safe template.

## Usage

Run passive collection with the memory store:

```powershell
.\.venv\Scripts\osint.exe run --domain example.com --max-depth 2
```

Run passive collection into Neo4j:

```powershell
.\.venv\Scripts\osint.exe run --domain example.com --max-depth 2 --store neo4j
```

Run a grounded investigation report:

```powershell
.\.venv\Scripts\osint.exe investigate --domain example.com --max-depth 2 --store neo4j --report out.md
```

Run with explicit authorization for exposure enrichment:

```powershell
.\.venv\Scripts\osint.exe investigate --domain scanme.nmap.org --authorize 45.33.32.156 --max-depth 2 --store neo4j --report out.md
```

Run a username account-existence investigation:

```powershell
.\.venv\Scripts\osint.exe investigate --username your-handle --investigation-reason "authorized self-test"
```

## Useful Neo4j Queries

Show ASN ownership chains:

```cypher
MATCH (a:ASN)-[:ANNOUNCES]->(n:Netblock)-[:CONTAINS]->(ip:IPAddress)
RETURN a, n, ip
```

Show hosted services on authorized IPs:

```cypher
MATCH (ip:IPAddress)-[:HOSTS]->(s:Service)
RETURN ip, s
```

Show high-priority or KEV vulnerabilities:

```cypher
MATCH (ip:IPAddress)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.kev = true OR v.cvss >= 9.0
RETURN ip, v
ORDER BY v.cvss DESC
```

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The suite uses mocked HTTP for connector behavior. Neo4j-backed tests run when Neo4j is reachable and skip when it is not.

## Project Structure

```text
src/osint/core/          Entity, relationship, ID, and provenance models
src/osint/connectors/    Passive and scoped enrichment connectors
src/osint/orchestrator/  Pivot policy, budgets, authorization, and engine loop
src/osint/store/         Memory and Neo4j stores
src/osint/agent/         LLM client, tools, validation, and report rendering
tests/                   Unit, integration, and safety tests
docs/                    Project documentation and sample report
```

## Design Notes

The system follows these design principles:

- Record first, enrich second: discovered facts are stored even when deeper enrichment is gated.
- Keep scope explicit: exposure data requires authorization.
- Treat LLM output as untrusted: every claim must cite graph evidence and survive validation.
- Prefer deterministic IDs and merge behavior so repeated runs are stable.
- Keep source provenance on every entity and relationship.

See [DESIGN.md](DESIGN.md) for the full architecture, data model, connector contract, confidence rules, and phased roadmap.

## Status

Implemented through Phase 11:

- Phase 1-4: core graph engine, crt.sh, Wayback, Neo4j, multi-hop pivoting, DNS.
- Phase 5: resilience layer with cache, retry, and circuit breaking.
- Phase 6: InternetDB service enrichment behind authorization.
- Phase 7: grounded LLM agent and provider-agnostic client.
- Phase 8: Cert Spotter redundancy and Neo4j write hardening.
- Phase 9: username account-existence enumeration with safety framing.
- Phase 10: ASN/netblock enrichment and identification-vs-exposure split.
- Phase 11: Vulnerability entity, CVEDB enrichment, and queryable Neo4j vulnerability fields.

## License

MIT. See [LICENSE](LICENSE).
