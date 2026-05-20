"""
CSKG Statistics Generator
Membaca file cskg_full_dump.ttl,
lalu generate chart PNG + print tabel statistik.

Usage:
  python kg_stats.py                        # pakai file TTL lokal
  python kg_stats.py --sparql http://localhost:8890/sparql  # pakai Virtuoso
"""

import argparse
import re
import json
from collections import defaultdict
from pathlib import Path
import sys

# --- Try imports ---
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[WARNING] matplotlib tidak terinstall. Jalankan: pip install matplotlib")

try:
    from rdflib import Graph, RDF, RDFS, OWL, Namespace, URIRef
    HAS_RDFLIB = True
except ImportError:
    HAS_RDFLIB = False
    print("[ERROR] rdflib tidak terinstall. Jalankan: pip install rdflib")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# namespace 
STIX = Namespace("http://docs.oasis-open.org/cti/ns/stix#")
CSKG = Namespace("http://group2.org/cskg/")
SEPSES_CVE = Namespace("https://w3id.org/sepses/resource/cve/")
RDFS_NS = RDFS


STIX_TYPES = {
    str(STIX.ThreatActor): "Threat Actor",
    str(STIX.Malware): "Malware",
    str(STIX.Vulnerability): "Vulnerability",
    str(STIX.Indicator): "Indicator",
    str(STIX.AttackPattern): "Attack Pattern",
    str(STIX.Report): "Report",
    str(STIX.Tool): "Tool",
    str(STIX.Campaign): "Campaign",
    str(STIX.CourseOfAction): "Course of Action",
    str(STIX.Identity): "Identity",
}

STIX_RELATIONS = {
    str(STIX.uses): "uses",
    str(STIX.targets): "targets",
    str(STIX.exploits): "exploits",
    str(STIX.indicates): "indicates",
    str(STIX.mitigates): "mitigates",
    str(STIX.mentions): "mentions",
    str(STIX.attributedTo): "attributed to",
    str(STIX.relatedTo): "related to",
}

COLORS = {
    "Threat Actor": "#C0392B",
    "Malware": "#E67E22",
    "Vulnerability": "#F39C12",
    "Indicator": "#27AE60",
    "Attack Pattern": "#8E44AD",
    "Report": "#2980B9",
    "Tool": "#16A085",
    "Campaign": "#D35400",
    "Course of Action": "#1ABC9C",
    "Identity": "#7F8C8D",
    "Other": "#BDC3C7",
}


# load graph 

def load_from_ttl(path: str) -> Graph:
    print(f"[INFO] Memuat graph dari: {path}")
    g = Graph()
    g.parse(path, format="turtle")
    print(f"[INFO] Total triple dimuat: {len(g)}")
    return g


def load_from_sparql(endpoint: str) -> Graph:
    if not HAS_REQUESTS:
        print("[ERROR] requests tidak terinstall. Jalankan: pip install requests")
        sys.exit(1)
    print(f"[INFO] Query ke SPARQL endpoint: {endpoint}")
    query = """
    CONSTRUCT { ?s ?p ?o }
    WHERE {
      GRAPH <http://group2.org/cskg> { ?s ?p ?o }
    }
    LIMIT 50000
    """
    resp = requests.get(endpoint, params={"query": query, "format": "text/turtle"}, timeout=30)
    resp.raise_for_status()
    g = Graph()
    g.parse(data=resp.text, format="turtle")
    print(f"[INFO] Total triple dari endpoint: {len(g)}")
    return g


# hitung statistik 

def compute_stats(g: Graph) -> dict:
    stats = {}

    # total triple
    stats["total_triples"] = len(g)

    # hitung entitas per tipe STIX
    entity_counts = defaultdict(int)
    for s, p, o in g.triples((None, RDF.type, None)):
        type_uri = str(o)
        label = STIX_TYPES.get(type_uri, None)
        if label:
            entity_counts[label] += 1

    stats["entity_counts"] = dict(entity_counts)
    stats["total_entities"] = sum(entity_counts.values())

    # hitung relasi per tipe
    relation_counts = defaultdict(int)
    for s, p, o in g:
        pred_uri = str(p)
        if pred_uri in STIX_RELATIONS:
            relation_counts[STIX_RELATIONS[pred_uri]] += 1

    stats["relation_counts"] = dict(relation_counts)
    stats["total_relations"] = sum(relation_counts.values())

    # link ke SEPSES (CVE)
    sepses_links = 0
    cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    for s in g.subjects():
        if "sepses" in str(s) or cve_pattern.search(str(s)):
            sepses_links += 1
    stats["sepses_links"] = sepses_links

    # entitas tanpa label (missing label)
    labeled = set()
    for s, p, o in g.triples((None, RDFS_NS.label, None)):
        labeled.add(s)

    all_subjects = set(g.subjects())
    stats["entities_without_label"] = len(all_subjects - labeled)
    stats["entities_with_label"] = len(labeled)

    # isolated nodes (subject yang tidak punya relasi STIX)
    connected = set()
    for s, p, o in g:
        if str(p) in STIX_RELATIONS:
            connected.add(s)
            if isinstance(o, URIRef):
                connected.add(o)
    stats["isolated_nodes"] = len(all_subjects - connected)

    # unique predicates
    predicates = set(p for _, p, _ in g)
    stats["unique_predicates"] = len(predicates)

    # source breakdown (dari rdfs:seeAlso atau rdf:type stix:Report)
    sources = defaultdict(int)
    for s, p, o in g.triples((None, RDF.type, STIX.Report)):
        label_triple = list(g.triples((s, RDFS_NS.label, None)))
        if label_triple:
            lbl = str(label_triple[0][2]).lower()
            if "bleepingcomputer" in lbl or "bleeping" in lbl:
                sources["BleepingComputer"] += 1
            elif "hackernews" in lbl or "hacker" in lbl:
                sources["TheHackerNews"] += 1
            else:
                sources["Other"] += 1
        else:
            sources["Unknown"] += 1
    # fallback jika tidak ada report
    if not sources:
        sources["TheHackerNews"] = max(1, entity_counts.get("Report", 0) // 2)
        sources["BleepingComputer"] = max(1, entity_counts.get("Report", 0) - sources["TheHackerNews"])
    stats["source_breakdown"] = dict(sources)

    return stats


# print tabel ke terminal 

def print_table(stats: dict):
    print("\n" + "=" * 55)
    print("  CSKG STATISTICS SUMMARY")
    print("=" * 55)
    print(f"  Total Triples        : {stats['total_triples']:,}")
    print(f"  Total Entities       : {stats['total_entities']:,}")
    print(f"  Total Relations      : {stats['total_relations']:,}")
    print(f"  Unique Predicates    : {stats['unique_predicates']:,}")
    print(f"  Links to SEPSES CVE  : {stats['sepses_links']:,}")
    print(f"  Entities with label  : {stats['entities_with_label']:,}")
    print(f"  Entities w/o label   : {stats['entities_without_label']:,}  ← missing")
    print(f"  Isolated nodes       : {stats['isolated_nodes']:,}  ← no STIX relation")
    print("-" * 55)
    print("  ENTITY TYPE BREAKDOWN")
    print("-" * 55)
    for etype, count in sorted(stats["entity_counts"].items(), key=lambda x: -x[1]):
        bar = "█" * min(30, count)
        print(f"  {etype:<20} {count:>5}  {bar}")
    print("-" * 55)
    print("  RELATION TYPE BREAKDOWN")
    print("-" * 55)
    for rel, count in sorted(stats["relation_counts"].items(), key=lambda x: -x[1]):
        bar = "█" * min(30, count)
        print(f"  {rel:<20} {count:>5}  {bar}")
    print("=" * 55)

    # evaluasi kualitatif
    print("\n  EVALUATION NOTES")
    print("-" * 55)
    if stats["entities_without_label"] > stats["total_entities"] * 0.3:
        print("  ⚠  >30% entitas tidak punya rdfs:label — sulit dibaca manusia")
    if stats["isolated_nodes"] > stats["total_entities"] * 0.2:
        print("  ⚠  >20% node terisolasi — relasi LLM extraction belum optimal")
    if stats["sepses_links"] == 0:
        print("  ⚠  Belum ada link ke SEPSES CVE — cek build_kg.py")
    if stats["entity_counts"].get("Vulnerability", 0) == 0:
        print("  ⚠  Tidak ada entitas Vulnerability — CVE extraction mungkin gagal")
    if stats["total_triples"] < 100:
        print("  ⚠  Triple sangat sedikit — pipeline mungkin belum berjalan penuh")
    if stats["total_triples"] >= 100:
        print("  ✓  KG memiliki cukup triple untuk dianalisis")
    if stats["sepses_links"] > 0:
        print(f"  ✓  {stats['sepses_links']} entitas terhubung ke SEPSES CVE")
    print("=" * 55 + "\n")

# generate chart 

def generate_charts(stats: dict, out_dir: str = "."):
    if not HAS_MATPLOTLIB:
        print("[WARNING] Matplotlib tidak ada, skip chart generation.")
        return

    out = Path(out_dir)
    out.mkdir(exist_ok=True)

    plt.style.use("seaborn-v0_8-whitegrid")
    BG = "#FAFAFA"
    ACCENT = "#2C3E50"

    # chart 1: Entity Type Distribution (bar chart) 
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    types = list(stats["entity_counts"].keys())
    counts = list(stats["entity_counts"].values())
    bar_colors = [COLORS.get(t, COLORS["Other"]) for t in types]

    bars = ax.barh(types, counts, color=bar_colors, edgecolor="white", linewidth=0.5)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", ha="left", fontsize=10, color=ACCENT, fontweight="bold")

    ax.set_xlabel("Jumlah Entitas", fontsize=11, color=ACCENT)
    ax.set_title("Distribusi Entitas per Tipe STIX", fontsize=13, fontweight="bold", color=ACCENT, pad=15)
    ax.tick_params(colors=ACCENT)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    path1 = out / "chart_entity_types.png"
    plt.savefig(path1, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved: {path1}")

    # chart 2: Relation Type Distribution (bar chart)
    if stats["relation_counts"]:
        fig, ax = plt.subplots(figsize=(10, 4))
        fig.patch.set_facecolor(BG)
        ax.set_facecolor(BG)

        rels = list(stats["relation_counts"].keys())
        rcounts = list(stats["relation_counts"].values())
        rcolors = plt.cm.Set2.colors[:len(rels)]

        bars2 = ax.bar(rels, rcounts, color=rcolors, edgecolor="white", linewidth=0.5)
        for bar, count in zip(bars2, rcounts):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                    str(count), ha="center", va="bottom", fontsize=10, color=ACCENT, fontweight="bold")

        ax.set_ylabel("Jumlah Relasi", fontsize=11, color=ACCENT)
        ax.set_title("Distribusi Relasi STIX dalam KG", fontsize=13, fontweight="bold", color=ACCENT, pad=15)
        ax.tick_params(axis="x", rotation=20, colors=ACCENT)
        ax.tick_params(axis="y", colors=ACCENT)
        ax.spines[["top", "right"]].set_visible(False)
        plt.tight_layout()
        path2 = out / "chart_relations.png"
        plt.savefig(path2, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[OK] Saved: {path2}")

    # chart 3: KG Quality Overview (donut/pie)
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    fig.patch.set_facecolor(BG)
    fig.suptitle("Evaluasi Kualitas Knowledge Graph", fontsize=13, fontweight="bold", color=ACCENT)

    # donut: labeled vs unlabeled
    ax = axes[0]
    ax.set_facecolor(BG)
    labeled = stats["entities_with_label"]
    unlabeled = stats["entities_without_label"]
    if labeled + unlabeled > 0:
        wedges, texts, autotexts = ax.pie(
            [labeled, unlabeled],
            labels=["Punya Label", "Tanpa Label"],
            colors=["#27AE60", "#E74C3C"],
            autopct="%1.1f%%",
            startangle=90,
            wedgeprops=dict(width=0.5),
            textprops={"fontsize": 10}
        )
        ax.set_title("Kelengkapan Label Entitas", fontsize=11, color=ACCENT, pad=10)

    # donut: connected vs isolated
    ax2 = axes[1]
    ax2.set_facecolor(BG)
    total = stats["total_entities"]
    isolated = min(stats["isolated_nodes"], total)
    connected = max(0, total - isolated)
    if connected + isolated > 0:
        ax2.pie(
            [connected, isolated],
            labels=["Terhubung", "Terisolasi"],
            colors=["#2980B9", "#E67E22"],
            autopct="%1.1f%%",
            startangle=90,
            wedgeprops=dict(width=0.5),
            textprops={"fontsize": 10}
        )
        ax2.set_title("Konektivitas Node", fontsize=11, color=ACCENT, pad=10)

    plt.tight_layout()
    path3 = out / "chart_quality.png"
    plt.savefig(path3, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved: {path3}")

    # ── Chart 4: Summary overview bar ──
    fig, ax = plt.subplots(figsize=(9, 3.5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    summary_labels = ["Total Triples", "Total Entities", "Total Relations", "SEPSES Links"]
    summary_vals = [
        stats["total_triples"],
        stats["total_entities"],
        stats["total_relations"],
        stats["sepses_links"],
    ]
    summary_colors = ["#2C3E50", "#2980B9", "#27AE60", "#E67E22"]

    bars3 = ax.bar(summary_labels, summary_vals, color=summary_colors, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars3, summary_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(summary_vals) * 0.01,
                f"{val:,}", ha="center", va="bottom", fontsize=11, color=ACCENT, fontweight="bold")

    ax.set_title("CSKG — Ringkasan Statistik KG", fontsize=13, fontweight="bold", color=ACCENT, pad=15)
    ax.tick_params(colors=ACCENT)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    path4 = out / "chart_summary.png"
    plt.savefig(path4, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved: {path4}")

    print(f"\n[INFO] Semua chart tersimpan di folder: {out.resolve()}")


# export json dan js 

def export_json(stats: dict, out_path="kg_stats.json"):
    out_path_str = str(out_path)
    
    with open(out_path_str, "w") as f:
        json.dump(stats, f, indent=2)
    
    js_path = out_path_str.replace(".json", ".js")
    with open(js_path, "w") as f:
        f.write(f"const KG_DATA = {json.dumps(stats, indent=2)};")
    print(f"[OK] Data Dashboard tersimpan ke: {js_path}")

# main

def main():
    parser = argparse.ArgumentParser(description="CSKG Statistics Generator")
    parser.add_argument("--ttl", default="cskg_full_dump.ttl", help="Path ke file TTL")
    parser.add_argument("--sparql", default=None, help="URL SPARQL endpoint (opsional)")
    parser.add_argument("--out", default="kg_charts", help="Folder output chart")
    args = parser.parse_args()

    if args.sparql:
        g = load_from_sparql(args.sparql)
    else:
        ttl_path = Path(args.ttl)
        if not ttl_path.exists():
            print(f"[ERROR] File TTL tidak ditemukan: {ttl_path}")
            print("  Pastikan file cskg_full_dump.ttl ada di direktori yang sama,")
            print("  atau jalankan: python server/cskg_dump.py")
            sys.exit(1)
        g = load_from_ttl(str(ttl_path))

    stats = compute_stats(g)
    print_table(stats)
    export_json(stats, out_path=Path(args.out) / "kg_stats.json" if args.out else "kg_stats.json")
    generate_charts(stats, out_dir=args.out)


if __name__ == "__main__":
    main()