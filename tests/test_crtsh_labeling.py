"""Regression tests for the crt.sh connector data-quality fixes.

These exercise `_record_to_finding` directly, so they need no HTTP mocking and
do not depend on the CollectionContext / respx fixtures used by test_crtsh.py.

Covers:
  #2  Co-SAN domains on other registrable domains must NOT inherit the seed's
      apex/tld, must still be created, must still be secured by the cert, but
      must NOT get a HAS_SUBDOMAIN edge from the seed root.
  #1  The Certificate entity must not claim a real sha256 it does not have; the
      local dedup key must be named honestly and the crt.sh id preserved.
"""

from __future__ import annotations

from osint.connectors.crtsh import CrtShConnector
from osint.core.entities import EntityType
from osint.core.relationships import RelationType


def _record() -> dict:
    return {
        "id": 999,
        "serial_number": "0A1B2C",
        "issuer_name": "C=US, O=Test CA",
        "common_name": "example.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        # Seed apex, an in-scope subdomain, and an UNRELATED co-SAN domain.
        "name_value": "example.com\napi.example.com\nexample.org",
    }


def _domains_by_value(finding) -> dict:
    return {e.value: e for e in finding.entities if e.type == EntityType.Domain}


def test_co_san_domain_does_not_inherit_seed_apex():
    finding = CrtShConnector()._record_to_finding(_record(), "example.com", "q", 0)
    domains = _domains_by_value(finding)

    # In-scope names inherit the seed apex.
    assert domains["example.com"].attributes["registered_domain"] == "example.com"
    assert domains["api.example.com"].attributes["registered_domain"] == "example.com"
    assert domains["api.example.com"].attributes["under_seed"] is True

    # The unrelated co-SAN domain must NOT be stamped with the seed's apex/tld.
    off = domains["example.org"]
    assert off.attributes["registered_domain"] is None
    assert off.attributes["tld"] == "org"
    assert off.attributes["under_seed"] is False
    assert "co-san" in off.tags


def test_co_san_domain_is_still_created_and_secured_but_not_a_subdomain():
    finding = CrtShConnector()._record_to_finding(_record(), "example.com", "q", 0)
    domains = _domains_by_value(finding)
    off = domains["example.org"]
    api = domains["api.example.com"]

    secures_targets = {
        r.dst_id for r in finding.relationships if r.type == RelationType.SECURES
    }
    has_sub_targets = {
        r.dst_id for r in finding.relationships if r.type == RelationType.HAS_SUBDOMAIN
    }

    # The cert secures the co-SAN domain (real, useful pivot signal)...
    assert off.id in secures_targets
    # ...but the seed does NOT claim it as a subdomain.
    assert off.id not in has_sub_targets
    # The genuine in-scope subdomain does get the HAS_SUBDOMAIN edge.
    assert api.id in has_sub_targets


def test_certificate_identity_is_named_honestly():
    finding = CrtShConnector()._record_to_finding(_record(), "example.com", "q", 0)
    cert = next(e for e in finding.entities if e.type == EntityType.Certificate)

    # We do not fabricate a sha256 we never received from crt.sh.
    assert cert.attributes["sha256"] is None
    # The local dedup key is present and honestly named.
    assert cert.attributes["synthetic_id"]
    assert cert.value == cert.attributes["synthetic_id"]
    # crt.sh's own record id is preserved for traceability.
    assert cert.attributes["crtsh_id"] == 999
