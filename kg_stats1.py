"""
KG Statistics & Evaluation Report — Issue #09
Cybersecurity Knowledge Graph from Unstructured Data
Group 6 | MRPL Class

Queries the live Virtuoso SPARQL endpoint, computes graph statistics,
and writes two output files:
  - kg_report.json   (machine-readable)
  - kg_report.md     (human-readable markdown)

Usage:
    python kg_stats.py
    python kg_stats.py --sparql http://localhost:8890/sparql
    python kg_stats.py --sparql http://localhost:8890/sparql --out ./reports
"""

import argparse
import json
import os
from datetime import datetime

import requests

# ── Config ──────────────────────────────────────────────────────────────────

DEFAULT_ENDPOINT = "http://localhost:8890/sparql"
GRAPH = "http://group2.org/cskg"

PREFIXES = """
PREFIX stix: <http://docs.oasis-open.org/cti/ns/stix#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>
"""

STIX_CLASSES = [
    "ThreatActor",
    "Malware",
    "AttackPattern",
    "Indicator",
    "Vulnerability",
    "Report",
    "Campaign",
    "CourseOfAction",
    "IntrusionSet",
    "Tool",
    "Identity",
]

STIX_RELATIONS = [
    "uses",
    "targets",
    "exploits",
    "indicates",
    "mitigates",
    "mentions",
    "attributedTo",
    "originatesFrom",
    "compromises",
    "delivers",
]


# ── SPARQL helpers ───────────────────────────────────────────────────────────

def sparql(endpoint: str, query: str) -> list[dict]:
    full = PREFIXES + "\n" + query
    r = requests.get(
        endpoint,
        params={"query": full, "format": "application/sparql-results+json"},
        timeout=30,
    )
    r.raise_for_status()
    bindings = r.json().get("results", {}).get("bindings", [])
    return [{k: v["value"] for k, v in b.items()} for b in bindings]


def scalar(endpoint: str, query: str, var: str) -> int:
    rows = sparql(endpoint, query)
    return int(rows[0][var]) if rows else 0


def shorten(uri: str) -> str:
    for ns, prefix in [
        ("http://docs.oasis-open.org/cti/ns/stix#", "stix:"),
        ("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "rdf:"),
        ("http://www.w3.org/2000/01/rdf-schema#", "rdfs:"),
        ("http://group2.org/cskg/", "cskg:"),
        ("https://w3id.org/sepses/resource/cve/", "sepses:"),
    ]:
        if uri.startswith(ns):
            return prefix + uri[len(ns):]
    # Strip long base URIs — keep last segment
    if uri.startswith("http"):
        return uri.rstrip("/").rsplit("/", 1)[-1]
    return uri


# ── Individual stat queries ──────────────────────────────────────────────────

def stat_total_triples(ep):
    return scalar(ep, f"""
SELECT (COUNT(*) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}""", "n")


def stat_unique_subjects(ep):
    return scalar(ep, f"""
SELECT (COUNT(DISTINCT ?s) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}""", "n")


def stat_unique_predicates(ep):
    return scalar(ep, f"""
SELECT (COUNT(DISTINCT ?p) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}""", "n")


def stat_unique_objects(ep):
    return scalar(ep, f"""
SELECT (COUNT(DISTINCT ?o) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o . FILTER(isIRI(?o)) }} }}""", "n")


def stat_literal_triples(ep):
    return scalar(ep, f"""
SELECT (COUNT(*) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o . FILTER(isLiteral(?o)) }} }}""", "n")


def stat_class_counts(ep):
    counts = {}
    for cls in STIX_CLASSES:
        n = scalar(ep, f"""
SELECT (COUNT(DISTINCT ?e) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?e a stix:{cls} }} }}""", "n")
        if n > 0:
            counts[cls] = n
    return counts


def stat_relation_counts(ep):
    counts = {}
    for rel in STIX_RELATIONS:
        n = scalar(ep, f"""
SELECT (COUNT(*) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s stix:{rel} ?o }} }}""", "n")
        if n > 0:
            counts[rel] = n
    return counts


def stat_top_predicates(ep, limit=15):
    rows = sparql(ep, f"""
SELECT ?p (COUNT(*) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o }} }}
GROUP BY ?p
ORDER BY DESC(?n)
LIMIT {limit}""")
    return [{"predicate": shorten(r["p"]), "count": int(r["n"])} for r in rows]


def stat_top_entities(ep, limit=10):
    """Most connected entities (highest out-degree)."""
    rows = sparql(ep, f"""
SELECT ?s (COUNT(*) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s ?p ?o . FILTER(isIRI(?s)) }} }}
GROUP BY ?s
ORDER BY DESC(?n)
LIMIT {limit}""")
    out = []
    for r in rows:
        label_rows = sparql(ep, f"""
SELECT ?label WHERE {{
  GRAPH <{GRAPH}> {{ <{r['s']}> rdfs:label ?label }}
}} LIMIT 1""")
        label = label_rows[0]["label"] if label_rows else shorten(r["s"])
        out.append({"entity": label, "uri": shorten(r["s"]), "triples": int(r["n"])})
    return out


def stat_cve_links(ep):
    """Count CVE URIs linked via SEPSES."""
    return scalar(ep, f"""
SELECT (COUNT(DISTINCT ?cve) AS ?n)
WHERE {{
  GRAPH <{GRAPH}> {{
    ?s ?p ?cve .
    FILTER(STRSTARTS(str(?cve), "https://w3id.org/sepses/resource/cve/"))
  }}
}}""", "n")


def stat_labelled_entities(ep):
    """Entities that have an rdfs:label."""
    return scalar(ep, f"""
SELECT (COUNT(DISTINCT ?s) AS ?n)
WHERE {{ GRAPH <{GRAPH}> {{ ?s rdfs:label ?l }} }}""", "n")


def stat_isolated_nodes(ep, total_subjects):
    """Entities that appear only as subjects with rdf:type (no other relations)."""
    only_typed = scalar(ep, f"""
SELECT (COUNT(DISTINCT ?s) AS ?n)
WHERE {{
  GRAPH <{GRAPH}> {{
    ?s a ?t .
    FILTER NOT EXISTS {{ ?s ?p ?o . FILTER(?p != rdf:type && ?p != rdfs:label) }}
  }}
}}""", "n")
    return only_typed


# ── Compute all stats ────────────────────────────────────────────────────────

def collect_all(ep: str) -> dict:
    print("  [1/9] Total triples…")
    total_triples = stat_total_triples(ep)

    print("  [2/9] Unique subjects / predicates / objects…")
    unique_subjects   = stat_unique_subjects(ep)
    unique_predicates = stat_unique_predicates(ep)
    unique_objects    = stat_unique_objects(ep)
    literal_triples   = stat_literal_triples(ep)

    print("  [3/9] Class counts…")
    class_counts = stat_class_counts(ep)

    print("  [4/9] Relation counts…")
    relation_counts = stat_relation_counts(ep)

    print("  [5/9] Top predicates…")
    top_predicates = stat_top_predicates(ep)

    print("  [6/9] Top connected entities…")
    top_entities = stat_top_entities(ep)

    print("  [7/9] CVE links…")
    cve_links = stat_cve_links(ep)

    print("  [8/9] Label coverage…")
    labelled = stat_labelled_entities(ep)

    print("  [9/9] Isolated nodes…")
    isolated = stat_isolated_nodes(ep, unique_subjects)

    # Derived metrics
    avg_triples_per_entity = round(total_triples / unique_subjects, 2) if unique_subjects else 0
    label_coverage_pct = round(100 * labelled / unique_subjects, 1) if unique_subjects else 0
    total_entities = sum(class_counts.values())
    cve_coverage_pct = round(100 * cve_links / class_counts.get("Vulnerability", 1), 1) \
        if class_counts.get("Vulnerability") else "N/A"

    return {
        "generated_at": datetime.now().isoformat(),
        "endpoint": ep,
        "graph": GRAPH,
        "graph_size": {
            "total_triples": total_triples,
            "unique_subjects": unique_subjects,
            "unique_predicates": unique_predicates,
            "unique_objects_iri": unique_objects,
            "literal_triples": literal_triples,
        },
        "derived": {
            "avg_triples_per_entity": avg_triples_per_entity,
            "label_coverage_pct": label_coverage_pct,
            "labelled_entities": labelled,
            "isolated_nodes": isolated,
        },
        "entity_distribution": class_counts,
        "relation_distribution": relation_counts,
        "top_predicates": top_predicates,
        "top_entities_by_degree": top_entities,
        "linked_data": {
            "cve_sepses_links": cve_links,
            "cve_link_coverage_pct": cve_coverage_pct,
        },
        "totals": {
            "typed_entities": total_entities,
        },
    }


# ── Markdown report ──────────────────────────────────────────────────────────

def render_markdown(stats: dict) -> str:
    s = stats
    g = s["graph_size"]
    d = s["derived"]
    ec = s["entity_distribution"]
    rc = s["relation_distribution"]

    lines = []
    def h(level, text): lines.append(f"{'#' * level} {text}\n")
    def p(text=""): lines.append(text)
    def table(headers, rows):
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
        for row in rows:
            lines.append("| " + " | ".join(str(c) for c in row) + " |")
        lines.append("")

    h(1, "CSKG Knowledge Graph — Statistics & Evaluation Report")
    p(f"**Generated:** {s['generated_at']}  ")
    p(f"**Graph URI:** `{s['graph']}`  ")
    p(f"**Endpoint:** `{s['endpoint']}`")
    p()

    # ── 1. Graph Size
    h(2, "1. Graph Size")
    table(
        ["Metric", "Value"],
        [
            ["Total triples",            f"{g['total_triples']:,}"],
            ["Unique subjects",           f"{g['unique_subjects']:,}"],
            ["Unique predicates",         f"{g['unique_predicates']:,}"],
            ["Unique object IRIs",        f"{g['unique_objects_iri']:,}"],
            ["Literal (data) triples",    f"{g['literal_triples']:,}"],
            ["Avg. triples per entity",   d["avg_triples_per_entity"]],
        ]
    )

    # ── 2. Entity Distribution
    h(2, "2. Entity Type Distribution")
    ec_rows = sorted(ec.items(), key=lambda x: x[1], reverse=True)
    total_typed = sum(ec.values())
    table(
        ["STIX Class", "Count", "% of typed entities"],
        [(cls, f"{n:,}", f"{100*n/total_typed:.1f}%") for cls, n in ec_rows]
    )
    p(f"**Total typed entities:** {total_typed:,}")
    p()

    # ── 3. Relation Distribution
    h(2, "3. Relation Type Distribution")
    rc_rows = sorted(rc.items(), key=lambda x: x[1], reverse=True)
    total_rels = sum(rc.values())
    table(
        ["STIX Relation", "Count", "% of relations"],
        [(f"`stix:{rel}`", f"{n:,}", f"{100*n/total_rels:.1f}%" if total_rels else "0%")
         for rel, n in rc_rows]
    )

    # ── 4. Top predicates
    h(2, "4. Top Predicates by Usage")
    table(
        ["Predicate", "Triple count"],
        [(r["predicate"], f"{r['count']:,}") for r in s["top_predicates"]]
    )

    # ── 5. Most connected entities
    h(2, "5. Most Connected Entities (by out-degree)")
    table(
        ["Entity", "URI", "Triples"],
        [(e["entity"], f"`{e['uri']}`", e["triples"]) for e in s["top_entities_by_degree"]]
    )

    # ── 6. Linked data quality
    h(2, "6. Linked Data & Label Quality")
    ld = s["linked_data"]
    table(
        ["Metric", "Value"],
        [
            ["CVE links to SEPSES KG",      f"{ld['cve_sepses_links']:,}"],
            ["CVE link coverage",            f"{ld['cve_link_coverage_pct']}%"],
            ["Entities with rdfs:label",     f"{d['labelled_entities']:,}"],
            ["Label coverage",               f"{d['label_coverage_pct']}%"],
            ["Isolated nodes (type-only)",   f"{d['isolated_nodes']:,}"],
        ]
    )

    # ── 7. Evaluation summary
    h(2, "7. Evaluation Summary")
    p("Since no ground-truth annotation file is available, this section provides a "
      "**structural evaluation** of the knowledge graph based on the statistics above.\n")

    h(3, "7.1 Completeness")
    p("Completeness is assessed by checking whether key STIX entity classes and "
      "relation types expected from CTI reports are present in the graph.\n")
    expected_classes = {"ThreatActor", "Malware", "Indicator", "Vulnerability",
                        "AttackPattern", "Report"}
    found = expected_classes & set(ec.keys())
    missing = expected_classes - found
    p(f"- **Expected STIX classes present:** {len(found)}/{len(expected_classes)} "
      f"({', '.join(sorted(found))})")
    if missing:
        p(f"- **Missing classes:** {', '.join(sorted(missing))}")
    p()

    expected_rels = {"uses", "targets", "exploits", "mentions"}
    found_rels = expected_rels & set(rc.keys())
    missing_rels = expected_rels - found_rels
    p(f"- **Expected STIX relations present:** {len(found_rels)}/{len(expected_rels)} "
      f"({', '.join(sorted(found_rels))})")
    if missing_rels:
        p(f"- **Missing relations:** {', '.join(sorted(missing_rels))}")
    p()

    h(3, "7.2 Label Coverage")
    lc = d['label_coverage_pct']
    level = "✅ Good" if lc >= 80 else ("⚠️ Moderate" if lc >= 50 else "❌ Low")
    p(f"**{lc}%** of entities have an `rdfs:label`. Rating: **{level}**\n")
    p("Label coverage reflects how human-readable the graph is and whether "
      "downstream applications (dashboards, queries) can surface meaningful names.\n")

    h(3, "7.3 Linked Data Quality")
    cve_cov = ld['cve_link_coverage_pct']
    p(f"**{ld['cve_sepses_links']}** CVE nodes are linked to the SEPSES CVE Knowledge Graph "
      f"(coverage: **{cve_cov}%**). ")
    p("Linking CVEs to an external authoritative KG increases interoperability and "
      "enables federated queries across datasets.\n")

    h(3, "7.4 Graph Density & Connectivity")
    p(f"- Average triples per entity: **{d['avg_triples_per_entity']}**")
    p(f"- Isolated (type-only) nodes: **{d['isolated_nodes']}** — "
      "these entities were extracted but no relations were found for them.")
    p()

    h(3, "7.5 Overall Assessment")
    p("| Dimension | Status | Notes |")
    p("| --- | --- | --- |")
    p(f"| Entity extraction | {'✅' if total_typed > 0 else '❌'} | "
      f"{total_typed} typed entities across {len(ec)} classes |")
    p(f"| Relation extraction | {'✅' if total_rels > 0 else '❌'} | "
      f"{total_rels} relation triples across {len(rc)} types |")
    p(f"| Label coverage | {'✅' if lc >= 80 else '⚠️'} | {lc}% |")
    p(f"| External linking (SEPSES) | {'✅' if ld['cve_sepses_links'] > 0 else '⚠️'} | "
      f"{ld['cve_sepses_links']} CVE links |")
    p(f"| Isolated nodes | {'✅' if d['isolated_nodes'] == 0 else '⚠️'} | "
      f"{d['isolated_nodes']} entities with no relations |")
    p()

    p("---")
    p("*Report generated by `kg_stats.py` — Issue #09, Group 6*")

    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CSKG Statistics & Evaluation Report (Issue #09)")
    parser.add_argument("--sparql", default=DEFAULT_ENDPOINT)
    parser.add_argument("--out", default=".", help="Output directory for report files")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  CSKG Statistics & Evaluation Report — Issue #09")
    print(f"  Endpoint : {args.sparql}")
    print(f"  Graph    : {GRAPH}")
    print(f"{'='*60}\n")

    try:
        stats = collect_all(args.sparql)
    except requests.exceptions.ConnectionError:
        print(f"\n[ERROR] Cannot connect to {args.sparql}")
        print("Make sure Virtuoso is running: docker compose up -d\n")
        raise SystemExit(1)

    # Save JSON
    json_path = os.path.join(args.out, "kg_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"\n  [✓] JSON report saved → {json_path}")

    # Save Markdown
    md_path = os.path.join(args.out, "kg_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(stats))
    print(f"  [✓] Markdown report saved → {md_path}")

    # Print summary to console
    g = stats["graph_size"]
    ec = stats["entity_distribution"]
    rc = stats["relation_distribution"]
    print(f"""
  ┌─────────────────────────────────────┐
  │  Graph Summary                      │
  ├─────────────────────────────────────┤
  │  Total triples      : {g['total_triples']:>10,}   │
  │  Unique entities    : {g['unique_subjects']:>10,}   │
  │  Unique predicates  : {g['unique_predicates']:>10,}   │
  │  Entity classes     : {len(ec):>10,}   │
  │  Relation types     : {len(rc):>10,}   │
  │  CVE links (SEPSES) : {stats['linked_data']['cve_sepses_links']:>10,}   │
  │  Label coverage     : {stats['derived']['label_coverage_pct']:>9}%   │
  └─────────────────────────────────────┘
""")


if __name__ == "__main__":
    main()
