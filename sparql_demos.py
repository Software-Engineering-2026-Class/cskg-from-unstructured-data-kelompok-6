"""
CSKG SPARQL Use-Case Demos — Issue #08
Cybersecurity Knowledge Graph from Unstructured Data
Group 6 | MRPL Class

3 real-world use-case demos that query the live Virtuoso SPARQL endpoint.

Usage:
    # Ensure the stack is running:
    #   docker compose up -d
    python sparql_demos.py

    # Or point to a different endpoint:
    python sparql_demos.py --sparql http://localhost:8890/sparql
"""

import argparse
import json
import sys
import textwrap
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_SPARQL_ENDPOINT = "http://localhost:8890/sparql"
CSKG_GRAPH = "http://group2.org/cskg"

PREFIXES = """
PREFIX cskg:   <http://group2.org/cskg/>
PREFIX stix:   <http://docs.oasis-open.org/cti/ns/stix#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
PREFIX sepses: <https://w3id.org/sepses/resource/cve/>
PREFIX xsd:    <http://www.w3.org/2001/XMLSchema#>
"""

# ---------------------------------------------------------------------------
# Helper: run a SPARQL SELECT against Virtuoso
# ---------------------------------------------------------------------------

def run_query(endpoint: str, query: str) -> list[dict]:
    """Execute a SPARQL SELECT query and return rows as list of dicts."""
    full_query = PREFIXES + "\n" + query
    resp = requests.get(
        endpoint,
        params={"query": full_query, "format": "application/sparql-results+json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    bindings = data.get("results", {}).get("bindings", [])
    rows = []
    for b in bindings:
        row = {k: v.get("value", "") for k, v in b.items()}
        rows.append(row)
    return rows


def print_section(title: str, width: int = 72):
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def print_table(rows: list[dict], max_col_width: int = 45):
    if not rows:
        print("  (no results)")
        return
    headers = list(rows[0].keys())
    # Compute column widths
    widths = {h: max(len(h), min(max(len(r.get(h, "")) for r in rows), max_col_width))
              for h in headers}
    sep = "  " + "-+-".join("-" * widths[h] for h in headers)
    header_row = "  " + " | ".join(h.ljust(widths[h]) for h in headers)
    print(sep)
    print(header_row)
    print(sep)
    for row in rows:
        cells = []
        for h in headers:
            val = row.get(h, "")
            # Strip URI prefixes for readability
            for prefix, short in [
                ("http://docs.oasis-open.org/cti/ns/stix#", "stix:"),
                ("http://group2.org/cskg/", "cskg:"),
                ("https://w3id.org/sepses/resource/cve/", "sepses:"),
            ]:
                val = val.replace(prefix, short)
            cells.append(val[:max_col_width].ljust(widths[h]))
        print("  " + " | ".join(cells))
    print(sep)
    print(f"  {len(rows)} result(s)\n")


# ===========================================================================
# USE CASE 1 — Threat Actor Profiling
# ===========================================================================

UC1_DESCRIPTION = """\
Use Case 1: Threat Actor Profiling
-----------------------------------
Question: "What malware, attack patterns, and targeted indicators are
associated with a given threat actor?"

Scenario: A SOC analyst receives an alert mentioning a known threat group.
They need a full capability profile to understand the scope of the threat
and prioritise detection rules.

This query retrieves all malware, attack patterns, and indicators linked
to *every* ThreatActor in the graph, ordered by actor then asset type.
Analysts can filter by actor label in the WHERE clause.
"""

UC1_QUERY = f"""
SELECT DISTINCT
    ?actor_label
    ?asset_type
    ?asset_label
WHERE {{
  GRAPH <{CSKG_GRAPH}> {{
    ?actor a stix:ThreatActor ;
           rdfs:label ?actor_label .

    {{
      ?actor stix:uses ?asset .
      ?asset a stix:Malware ;
             rdfs:label ?asset_label .
      BIND("Malware" AS ?asset_type)
    }}
    UNION
    {{
      ?actor stix:uses ?asset .
      ?asset a stix:AttackPattern ;
             rdfs:label ?asset_label .
      BIND("AttackPattern" AS ?asset_type)
    }}
    UNION
    {{
      ?actor stix:targets ?asset .
      ?asset a stix:Indicator ;
             rdfs:label ?asset_label .
      BIND("Indicator" AS ?asset_type)
    }}
  }}
}}
ORDER BY ?actor_label ?asset_type ?asset_label
LIMIT 50
"""


# ===========================================================================
# USE CASE 2 — CVE-to-IOC Tracing
# ===========================================================================

UC2_DESCRIPTION = """\
Use Case 2: CVE-to-IOC Tracing
--------------------------------
Question: "Which threat actors exploit a specific CVE, and what indicators
of compromise (IOCs) are associated with those actors?"

Scenario: The CISO receives a vendor advisory for a newly-patched CVE.
Before patching, they want to know whether any active threat actors in the
graph are exploiting it and what IOCs defenders should immediately hunt for.

The query walks:
  CVE  <-- stix:exploits --  ThreatActor  -- stix:uses -->  Indicator
using the linked SEPSES URI for CVE identity.
"""

UC2_QUERY = f"""
SELECT DISTINCT
    ?cve_id
    ?actor_label
    ?indicator_label
WHERE {{
  GRAPH <{CSKG_GRAPH}> {{
    ?actor a stix:ThreatActor ;
           rdfs:label ?actor_label .

    ?actor stix:exploits ?cve .
    BIND(REPLACE(str(?cve), "https://w3id.org/sepses/resource/cve/", "") AS ?cve_id)

    OPTIONAL {{
      ?actor stix:uses ?indicator .
      ?indicator a stix:Indicator ;
                 rdfs:label ?indicator_label .
    }}
  }}
}}
ORDER BY ?cve_id ?actor_label
LIMIT 60
"""


# ===========================================================================
# USE CASE 3 — Campaign Timeline & Report Provenance
# ===========================================================================

UC3_DESCRIPTION = """\
Use Case 3: Campaign Timeline & Report Provenance
--------------------------------------------------
Question: "When were reports about a threat actor published, and what
entities (malware, CVEs) did each report mention?"

Scenario: An incident responder is building a timeline for a post-incident
review. They need to know which published reports reference the relevant
threat actor, what malware and CVEs each report surfaces, and the
chronological order — so they can correlate intrusion activity with
public disclosure dates.

The query collects stix:Report nodes, their timestamps, and all entities
those reports mention, grouped by actor for narrative coherence.
"""

UC3_QUERY = f"""
SELECT DISTINCT
    ?actor_label
    ?report_url
    ?entity_label
    ?entity_type
WHERE {{
  GRAPH <{CSKG_GRAPH}> {{
    ?actor a stix:ThreatActor ;
           rdfs:label ?actor_label .

    ?report a stix:Report ;
            stix:mentions ?actor .

    OPTIONAL {{
      ?report stix:mentions ?entity .
      ?entity a ?entity_type ;
              rdfs:label ?entity_label .
      FILTER(?entity != ?actor)
      FILTER(CONTAINS(str(?entity_type), "stix"))
    }}

    BIND(str(?report) AS ?report_url)
  }}
}}
ORDER BY ?actor_label ?report_url
LIMIT 60
"""


# ===========================================================================
# Main runner
# ===========================================================================

USE_CASES = [
    ("Use Case 1: Threat Actor Profiling",          UC1_DESCRIPTION, UC1_QUERY),
    ("Use Case 2: CVE-to-IOC Tracing",              UC2_DESCRIPTION, UC2_QUERY),
    ("Use Case 3: Campaign Timeline & Provenance",  UC3_DESCRIPTION, UC3_QUERY),
]


def save_results_json(results_all: list, path: str):
    out = []
    for title, desc, _, rows in results_all:
        out.append({"use_case": title, "description": desc, "results": rows})
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  [✓] JSON results saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="CSKG SPARQL Use-Case Demos (Issue #08)")
    parser.add_argument("--sparql", default=DEFAULT_SPARQL_ENDPOINT,
                        help="Virtuoso SPARQL endpoint URL")
    parser.add_argument("--json-out", default=None,
                        help="Optional path to save results as JSON")
    args = parser.parse_args()

    print(f"\n{'#' * 72}")
    print(f"  CSKG SPARQL Use-Case Demos — Issue #08")
    print(f"  Endpoint : {args.sparql}")
    print(f"  Graph    : {CSKG_GRAPH}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print(f"{'#' * 72}")

    collected = []
    for title, description, query in USE_CASES:
        print_section(title)
        print(textwrap.indent(description.strip(), "  "))
        print("\n  Running query…")
        try:
            rows = run_query(args.sparql, query)
            print_table(rows)
            collected.append((title, description, query, rows))
        except requests.exceptions.ConnectionError:
            print(f"\n  [ERROR] Could not connect to {args.sparql}")
            print("  Make sure 'docker compose up -d' is running first.\n")
            sys.exit(1)
        except Exception as exc:
            print(f"\n  [ERROR] {exc}\n")
            collected.append((title, description, query, []))

    if args.json_out:
        save_results_json(collected, args.json_out)

    print(f"\n{'#' * 72}")
    print("  All use-case demos complete.")
    print(f"{'#' * 72}\n")


if __name__ == "__main__":
    main()
