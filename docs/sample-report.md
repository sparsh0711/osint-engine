# Sample Investigation Report

This is a sanitized example of the report shape produced by `osint investigate`.

## Findings

### High Priority

No validated findings.

### Medium Priority

- **A discovered IP address is present in the graph but has not been service-enriched.**
  Rationale: Passive DNS identified an IP address related to the investigated domain, but no authorized service-enrichment pass has been run for that IP.
  Cites: IPAddress 203.0.113.10 (example-id)
  Relationships: none
  Sources: dns/dns confidence=0.90

### Low Priority

No validated findings.

## Recommended Next Steps

- **Authorize and run service enrichment for the discovered IP address.**: 203.0.113.10
  Rationale: Service enrichment can identify exposed ports and improve graph context, but it should only run with explicit authorization.
  Authorization required: Authorization required before active or scope-expanding work

## Rejected/unverifiable claims

None.
