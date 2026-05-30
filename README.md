# Constructing a Cybersecurity Knowledge Graph (CSKG) from Unstructured Data

This project is a fork of an existing implementation of an automated data pipeline to construct a Cybersecurity Knowledge Graph (CSKG) from unstructured data sources like security blogs and attack reports. It is made as a final project for MRPL (Metode Rekayasa Perangkat Lunak) class.

## 0. Our Team Members

We are Group 6 which includes these amazing guys:
| Name     | NIM | Username |
| ---      | ---       | --- |
| Dhimas Early Oceandy (PIC) | 24/533508/PA/22584 | EarlyOcean |
| Anders Emmanuel Tan     | 24/541351/PA/22964 | Plumz17 | 
| Azhar Maulana | 24/533487/PA/22582 | naa2412 |
| Evan Razzan Adytaputra | 24/545257/PA/23166| evanrazzanadytaputra2006-dotcom | 

## 1. Unstructured Sources

Our implementation uses the previously implemented source
**Security News Blogs (RSS)**
as well as 2 additional sources:
1. **NVD CSE API**
2. **CIRCL CVE**

## 2. Ontology

We use a hybrid ontology approach, combining a well-established, existing ontology with a custom namespace for our graph.

* **Primary Ontology: STIX 2.1**
    We use the [STIX (Structured Threat Information Expression)](http://docs.oasis-open.org/cti/ns/stix#) namespace as our primary ontology. It is the industry standard for cybersecurity threat intelligence. Our `pipeline/build_kg.py` file explicitly maps extracted entities to STIX classes:

    * `STIX.ThreatActor`
    * `STIX.Malware`
    * `STIX.Vulnerability`
    * `STIX.Indicator`
    * `STIX.AttackPattern`
    * `STIX.Report`

* **Custom Namespace: `cskg`**
    We use our own namespace, `http://group2.org/cskg/`, for our named graph and for any entities that do not have a clear STIX equivalent.

* **Relationship Mapping**
    A key feature is the `RELATIONSHIP_MAP` in `pipeline/build_kg.py`. This maps plain-English verbs extracted by the LLM (e.g., "uses", "targets") directly to their formal STIX relationship properties (e.g., `STIX.uses`, `STIX.targets`). This ensures our graph is ontologically consistent.

## 3. Pipeline Architecture

This project is built as an event-driven, microservice-based pipeline orchestrated by `docker-compose.yml`.

1.  **`producer` (`pipeline/scraper.py`)**
    * A Python script that scrapes RSS feeds for new articles.
    * It checks for duplicates using a Redis `set` (`seen_urls`).
    * **Output:** Pushes new article (JSON) to the `articles_queue` in Redis.

2.  **`extractor` (`pipeline/extractor_worker.py`)**
    * A Python worker that listens to the `articles_queue`.
    * It uses a **LangChain** pipeline (`pipeline/extractor.py`) built with a Google Gemini LLM and Pydantic output parsers.
    * The LLM is prompted to extract entities (Threat Actors, Malware, CVEs, Indicators) and their relationships (e.g., "APT29 *uses* new_malware").
    * **Output:** Pushes the structured extraction (JSON) to the `extractions_queue` in Redis.

3.  **`graph_builder` (`pipeline/builder_worker.py`)**
    * A Python worker that listens to the `extractions_queue`.
    * It uses `rdflib` to transform the JSON extraction into RDF triples, mapping them to the STIX ontology (from `build_kg.py`).
    * **Output:** Connects to Virtuoso and executes a SPARQL `INSERT DATA` query to add the new triples to our named graph (`<http://group2.org/cskg>`).

4.  **`summary` (`pipeline/graph_eval_worker.py`)**
    * A periodic worker that runs daily to assess the state of the knowledge graph.
    * It queries the graph for all known Threat Actor capabilities and uses the LLM to generate a "Strategic Threat Landscape Assessment."
    * **Output:** Saves a comprehensive Markdown report to the `reports/` directory (e.g., `reports/strategic_assessment_2025-11-21.md`).

5.  **`redis`**
    * A Redis container that acts as the message bus (queuing system) between the producer, extractor, and builder.

6.  **`virtuoso`**
    * The OpenLink Virtuoso container, which provides the persistent SPARQL endpoint. All triples are stored here.
    * **SPARQL Endpoint:** `http://localhost:8890/sparql`
    * **SQL scripts:** `pipeline/virtuoso-scripts/init.sql` runs on startup to set the correct permissions for the `SPARQL` user to be able to write to the graph.

7.  **`api` (`server/api_server.py`)**
    * A FastAPI server that provides a simple REST API to query the graph.
    * **Query Endpoint:** `POST /query`
    * **Status Endpoint:** `GET /` (Shows total triples)

## 4. Summary/Statistics of Constructed KG

The knowledge graph is dynamic and grows continuously as new articles are scraped from all configured sources.

### 4.1 Live Statistics

Get a real-time triple count via the API:

```
GET http://localhost:8000/
```

Example response:
```json
{
  "status": "online",
  "graph_db_backend": "Virtuoso",
  "sparql_endpoint": "http://virtuoso:8890/sparql",
  "total_triples": 5863
}
```

### 4.2 Generating Statistics & Visualizations

We provide a dedicated statistics script that queries the live Virtuoso endpoint and generates charts automatically.

```bash
# Install dependencies
pip install rdflib matplotlib requests

# Generate statistics and charts
mkdir kg_charts
python kg_stats.py --sparql http://localhost:8890/sparql --out kg_charts

# Open the interactive dashboard
# Double-click kg_dashboard.html in your file explorer
```

#### Known Issues & Limitations

- **Entity disambiguation**: The same threat actor may appear under multiple labels (e.g., `"APT29"` vs `"Cozy Bear"`) due to LLM variability — no deduplication/coreference resolution is currently implemented.
- **Relation sparsity**: Not all extracted entities receive relations — some appear only as isolated nodes when the LLM fails to identify a clear relationship.
- **Source imbalance**: RSS feed articles dominate the graph; NVD and CIRCL CVE entries contribute primarily `stix:Vulnerability` nodes with fewer interconnections.
- **Temporal coverage**: The graph reflects articles from the pipeline's runtime period only — no historical backfill.


## 5. Linking to Existing KGs

**This requirement is successfully implemented.**

Our pipeline explicitly links to the **SEPSES CVE Knowledge Graph**. The `pipeline/build_kg.py` script contains logic to detect if a vulnerability is a CVE:

```python
# Check if the vulnerability string is a CVE
cve_match = re.search(r"(CVE-\d{4}-\d{4,})", vuln, re.IGNORECASE)

if cve_match:
    # It's a CVE! Use the SEPSES URI.
    cve_id = cve_match.group(1).upper()
    vuln_uri = SEPSES_CVE[cve_id]  # e.g., .../cve/CVE-2023-1234
else:
    # Not a CVE, use our own namespace
    vuln_uri = safe_uri(MY_KG, vuln)
````

This ensures that when we add a triple like `(cskg:LockBit, stix:exploits, sepses:CVE-2023-1234)`, our graph is automatically linked to the rich, external data of the SEPSES CVE graph.

## 6\. Implementation Use Cases

Here are 3 real-world use cases for the constructed KG. All queries are
executed against the live Virtuoso endpoint at `http://localhost:8890/sparql`
and can also be run via `python sparql_demos.py`.

---

### Use Case 1: Threat Actor Profiling

**Scenario:** A SOC analyst receives an alert mentioning a known threat group.
They need a full capability profile — all malware, attack patterns, and
targeted indicators linked to that actor — to prioritise detection rules.

```sparql
PREFIX cskg:   <http://group2.org/cskg/>
PREFIX stix:   <http://docs.oasis-open.org/cti/ns/stix#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?actor_label ?asset_type ?asset_label
WHERE {
  GRAPH <http://group2.org/cskg> {
    ?actor a stix:ThreatActor ;
           rdfs:label ?actor_label .

    { ?actor stix:uses ?asset . ?asset a stix:Malware       ; rdfs:label ?asset_label . BIND("Malware"        AS ?asset_type) }
    UNION
    { ?actor stix:uses ?asset . ?asset a stix:AttackPattern ; rdfs:label ?asset_label . BIND("AttackPattern"  AS ?asset_type) }
    UNION
    { ?actor stix:targets ?asset . ?asset a stix:Indicator  ; rdfs:label ?asset_label . BIND("Indicator"      AS ?asset_type) }
  }
}
ORDER BY ?actor_label ?asset_type ?asset_label
LIMIT 50
```

**Live Result (from Virtuoso, 2026-05-30):**

| actor_label    | asset_type    | asset_label                          |
|----------------|---------------|--------------------------------------|
| cybercriminals | AttackPattern | Fraudulent code-signing              |
| cybercriminals | AttackPattern | fraudulent code-signing              |
| cybercriminals | Malware       | malware-signing-as-a-service (MSaaS) |

---

### Use Case 2: Vulnerability-to-Threat-Actor Tracing

**Scenario:** The CISO receives a vendor advisory for a newly-patched
vulnerability. Before patching, the security team queries the CSKG to
identify which tracked threat actors are actively exploiting it and what
other tools or IOCs those actors deploy.

```sparql
PREFIX cskg:   <http://group2.org/cskg/>
PREFIX stix:   <http://docs.oasis-open.org/cti/ns/stix#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:    <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT ?actor_label ?vuln_label ?ioc_label
WHERE {
  GRAPH <http://group2.org/cskg> {
    # Find canonical actor nodes that exploit a vulnerability
    ?actor a stix:ThreatActor ;
           stix:exploits ?vuln .
    ?vuln  a stix:Vulnerability ;
           rdfs:label ?vuln_label .

    # Resolve actor label: direct label OR via owl:sameAs alias
    OPTIONAL { ?actor rdfs:label ?lbl_direct . }
    OPTIONAL {
      ?alias owl:sameAs ?actor ;
             rdfs:label ?lbl_alias .
    }
    BIND(COALESCE(?lbl_direct, ?lbl_alias,
         REPLACE(str(?actor), "http://group2.org/cskg/", "")) AS ?actor_label)

    # Optional: IOCs or Malware the actor deploys
    OPTIONAL {
      ?actor stix:uses ?ioc .
      { ?ioc a stix:Indicator . } UNION { ?ioc a stix:Malware . }
      ?ioc rdfs:label ?ioc_label .
    }
  }
}
ORDER BY ?actor_label ?vuln_label
LIMIT 60
```

**Live Result (from Virtuoso, 2026-05-30):**

| actor_label              | vuln_label                                         | ioc_label |
|--------------------------|----------------------------------------------------|-----------|
| unauthenticated attackers | ChromaDB FastAPI vulnerability                    | —         |
| unauthenticated attackers | ChromaDB arbitrary code execution vulnerability   | —         |
| unauthenticated attackers | max-severity vulnerability in ChromaDB            | —         |

> **Note:** The `owl:sameAs` pattern is required here because the canonical
> (lowercase) actor nodes hold all STIX relationships, while human-readable
> `rdfs:label` values are stored on the raw alias nodes linked via
> `owl:sameAs`. This is a known graph modelling choice documented in Section 4.2.

---

### Use Case 3: Campaign Timeline & Report Provenance

**Scenario:** An incident responder is building a post-incident review
timeline. They query which published reports reference a threat actor,
what malware/CVEs each report surfaces, and the chronological order — so
intrusion activity can be correlated with public disclosure dates.

```sparql
PREFIX cskg:   <http://group2.org/cskg/>
PREFIX stix:   <http://docs.oasis-open.org/cti/ns/stix#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT ?actor_label ?report_url ?entity_label ?entity_type
WHERE {
  GRAPH <http://group2.org/cskg> {
    ?actor a stix:ThreatActor ;
           rdfs:label ?actor_label .

    ?report a stix:Report ;
            stix:mentions ?actor .

    OPTIONAL {
      ?report stix:mentions ?entity .
      ?entity a ?entity_type ;
              rdfs:label ?entity_label .
      FILTER(?entity != ?actor)
      FILTER(CONTAINS(str(?entity_type), "stix"))
    }

    BIND(str(?report) AS ?report_url)
  }
}
ORDER BY ?actor_label ?report_url
LIMIT 60
```

**Live Result (from Virtuoso, 2026-05-30):**

| actor_label    | report_url                                                                                                                            | entity_label                         | entity_type          |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------|----------------------|
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | Fraudulent code-signing              | stix:AttackPattern   |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | Malware-signing-as-a-service         | stix:AttackPattern   |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | malware-signing-as-a-service         | stix:AttackPattern   |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | Malware-signing-as-a-service         | stix:Malware         |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | malware-signing-as-a-service         | stix:Malware         |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | malware-signing-as-a-service (MSaaS) | stix:Malware         |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | code-signing                         | stix:AttackPattern   |
| cybercriminals | https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/ | fraudulent code-signing              | stix:AttackPattern   |

---

### Running All Demos

To reproduce all 3 use cases against a running stack:

```bash
# Ensure the stack is running
docker compose up -d

# Run all demos and save JSON output
python sparql_demos.py --sparql http://localhost:8890/sparql --json-out results.json
```

Or open `sparql_demo_ui.html` in a browser for an interactive interface.

**Screenshot — Live Demo Output:**

![SPARQL demo terminal output](docs/sparql_demo_output.png)

## 7\. Constructed KG (RDF/Turtle File)

The pipeline writes data *live* to the Virtuoso database.

To get a full dump of the *live* graph from the system, you can run the provided dump script from your local machine:

```bash
python server/cskg_dump.py
```

This will connect to the running Virtuoso instance and save the full Knowledge Graph as a `.ttl` file in your current directory.

## 8\. How to Run

1.  **Clone the repository:**

    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2.  **Create `.env` file:**
    This project requires a Google API key for the extractor.

    ```bash
    # Copy the example .env file
    # (Note: You'll need to create a .env.example if it's not there)
    # Create a new file named .env
    nano .env
    ```

    Add your API key to the `.env` file:

    ```
    GOOGLE_API_KEY=YOUR_API_KEY_HERE
    ```

3.  **Build and Run with Docker Compose:**

    ```bash
    docker compose up --build -d
    ```

      * `--build`: Forces Docker to rebuild the image (useful if you change code).
      * `-d`: Runs in detached mode.

4.  **Access the Services:**

      * **CSKG API:** `http://localhost:8000/docs`
      * **Virtuoso SPARQL UI:** `http://localhost:8890/sparql`
      * **Redis (e.g., with RedisInsight):** `redis://localhost:6379`

5.  **View Logs:**
    To see the pipeline in action, you can stream the logs:

    ```bash
    # See all services
    docker compose logs -f

    # See just the extractor, builder, and summary worker
    docker compose logs -f extractor graph_builder summary
    ```

## 9\. GitHub Source

The full source code for this project is available in this repository.
