# OSINT Investigation Report

## Findings

### High Priority

- **Four IPAddress entities lack associated host information (HOSTS relationships).**
  Rationale: The `list_unenriched_ips` function identified four IP addresses that do not have any `HOSTS` relationships in the graph, indicating a lack of contextual host information for these network entities. These IPs are 104.20.23.154, 172.66.147.243, 2606:4700:90c5:72db:f264:dc3:ef6b:ff98, and 2606:4700:90c5:72db:f2ef:b90:ef6b:ff98.
  Cites: IPAddress 104.20.23.154 (73b754a549dccb64), IPAddress 172.66.147.243 (dd029063848e7f3a), IPAddress 2606:4700:90c5:72db:f264:dc3:ef6b:ff98 (487a0ed6371bbcd9), IPAddress 2606:4700:90c5:72db:f2ef:b90:ef6b:ff98 (6aed24a14c3cc557)
  Relationships: none
  Sources: dns/dns confidence=0.90

### Medium Priority

No validated findings.

### Low Priority

No validated findings.

## Recommended Next Steps

- **Perform reverse DNS lookups on the unenriched IP addresses.**: 104.20.23.154, 172.66.147.243, 2606:4700:90c5:72db:f264:dc3:ef6b:ff98, 2606:4700:90c5:72db:f2ef:b90:ef6b:ff98
  Rationale: Enriching these IP addresses with reverse DNS information will help identify the associated hostnames, providing critical context for further investigation and understanding their role within the network. This will help establish `HOSTS` relationships.
  Authorization required: Authorization required before active work against 104.20.23.154, 172.66.147.243, 2606:4700:90c5:72db:f264:dc3:ef6b:ff98, 2606:4700:90c5:72db:f2ef:b90:ef6b:ff98

## Rejected/unverifiable claims

None.
