import re
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, DCTERMS, OWL  # Added DCTERMS and SKOS
from urllib.parse import quote

# --- 1. Define Namespaces ---
MY_KG = Namespace("http://group2.org/cskg/")
STIX = Namespace("http://docs.oasis-open.org/cti/ns/stix#")
SEPSES_CVE = Namespace("https://w3id.org/sepses/resource/cve/")
SEPSES_CWE = Namespace("https://w3id.org/sepses/resource/cwe/")

RELATIONSHIP_MAP = {
    "uses": STIX.uses,
    "targets": STIX.targets,
    "exploits": STIX.exploits,
    "mitigates": STIX.mitigates,
    "attributed_to": STIX.attributed_to,
    "variant_of": STIX.variant_of,
    "located_in": STIX.located_in,
    "impersonates": STIX.impersonates,
    "reports": STIX.reports,
    "patched": STIX.patched,
    "resolved": STIX.resolved,
    "disrupted": STIX.disrupted,
    "aligned_with": STIX.aligned_with,
    "observes": STIX.observes,
    "has_similarities_with": STIX.has_similarities_with,
    "propagated_via": STIX.propagated_via,
}


def build_graph(extractions, existing_graph=None):
    """Builds an RDF graph from the extracted entities and relations."""
    if existing_graph is not None:
        g = existing_graph
        print("Adding new triples to existing graph...")
    else:
        g = Graph()
        print("Building new RDF graph...")
        g.bind("cskg", MY_KG)
        g.bind("stix", STIX)
        g.bind("rdfs", RDFS)
        g.bind("dcterms", DCTERMS)  # Bind Dublin Core for dates
        g.bind("owl", OWL)  # Bind OWL for sameAs

    print("Building RDF graph...")

    # Helper function to create a Canonical URI (Normalizes data for linking)
    def safe_uri(namespace, text):
        if not text:
            return namespace["unknown"]
        # 1. Lowercase
        # 2. Remove all non-alphanumeric characters (removes spaces, dashes, dots)
        #    "APT-29" -> "apt29", "APT 29" -> "apt29"
        safe_text = re.sub(r"[\W_]+", "", text.lower())
        return namespace[safe_text]

    def unsafe_uri(namespace, text):
        # Keeps original formatting safe for URI
        return namespace[quote(text.replace(" ", "_"))]

    for item in extractions:
        report_url = item["source_url"]
        entities = item["entities"]

        # --- CHANGE: Get the Date ---
        published_date = item.get("published")

        # Create a URI for the report itself
        report_uri = URIRef(report_url)
        g.add((report_uri, RDF.type, STIX.Report))

        # --- CHANGE: Add Timestamp Triple ---
        if published_date and published_date != "N/A":
            g.add((report_uri, DCTERMS.created, Literal(published_date)))

        # --- 2. Add all named entities as nodes ---
        for actor in entities.get("threat_actors") or []:
            # 1. Generate both URIs
            raw_actor_uri = unsafe_uri(MY_KG, actor)  # e.g., cskg:APT_29
            canonical_actor_uri = safe_uri(MY_KG, actor)  # e.g., cskg:apt29

            # 2. Define the Canonical Node (This is the one relationships will use)
            g.add((canonical_actor_uri, RDF.type, STIX.ThreatActor))

            # 3. Define the Raw Node (This preserves the original label)
            g.add((raw_actor_uri, RDF.type, STIX.ThreatActor))
            g.add((raw_actor_uri, RDFS.label, Literal(actor)))

            # 4. Link Report to Canonical (Makes querying easier)
            g.add((report_uri, STIX.mentions, canonical_actor_uri))

            # 5. Link them with owl:sameAs
            if raw_actor_uri != canonical_actor_uri:
                g.add((raw_actor_uri, OWL.sameAs, canonical_actor_uri))

        for malware in entities.get("malware") or []:
            malware_uri = safe_uri(MY_KG, malware)
            g.add((malware_uri, RDF.type, STIX.Malware))
            g.add((malware_uri, RDFS.label, Literal(malware)))
            g.add((report_uri, STIX.mentions, malware_uri))

        for vuln in entities.get("vulnerabilities") or []:
            # --- CVE detection: link to SEPSES CVE KG ---
            cve_match = re.search(r"(CVE-\d{4}-\d{4,})", vuln, re.IGNORECASE)
            # --- CWE detection: link to SEPSES CWE KG ---
            cwe_match = re.search(r"(CWE-\d+)", vuln, re.IGNORECASE)

            if cve_match:
                cve_id = cve_match.group(1).upper()
                vuln_uri = SEPSES_CVE[cve_id]  # e.g., sepses:CVE-2023-1234
            elif cwe_match:
                cwe_id = cwe_match.group(1).upper()
                vuln_uri = SEPSES_CWE[cwe_id]  # e.g., sepses:CWE-79
            else:
                vuln_uri = safe_uri(MY_KG, vuln)

            g.add((vuln_uri, RDF.type, STIX.Vulnerability))
            g.add((vuln_uri, RDFS.label, Literal(vuln)))
            g.add((report_uri, STIX.mentions, vuln_uri))

        for ind in entities.get("indicators") or []:
            ind_uri = safe_uri(MY_KG, ind)
            g.add((ind_uri, RDF.type, STIX.Indicator))
            g.add((ind_uri, RDFS.label, Literal(ind)))
            g.add((report_uri, STIX.mentions, ind_uri))

        for pattern in entities.get("attack_patterns") or []:
            pattern_uri = safe_uri(MY_KG, pattern)
            g.add((pattern_uri, RDF.type, STIX.AttackPattern))
            g.add((pattern_uri, RDFS.label, Literal(pattern)))
            g.add((report_uri, STIX.mentions, pattern_uri))

        # --- 3. Add all relationships as edges ---
        for rel in entities.get("relations") or []:
            # Important: Relationships use safe_uri, so they attach to the Canonical Node
            subj_uri = safe_uri(MY_KG, rel["subject"])
            obj_uri = safe_uri(MY_KG, rel["object"])

            relationship_str = rel["relationship"]
            rel_prop = RELATIONSHIP_MAP.get(
                relationship_str, safe_uri(MY_KG, relationship_str)
            )

            g.add((subj_uri, rel_prop, obj_uri))

    return g
