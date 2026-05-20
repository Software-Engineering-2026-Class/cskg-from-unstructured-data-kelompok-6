# Constructing a Cybersecurity Knowledge Graph (CSKG) from Unstructured Data

This project is a fork of an existing implementation of an automated data pipeline to construct a Cybersecurity Knowledge Graph (CSKG) from unstructured data sources like security blogs and attack reports. It is made as a final project for MRPL (Metode Rekayasa Perangkat Lunak) class.

## 0. Our Team Members

We are Group 6 which includes these amazing guys:
1. **Dhimas Early Oceandy (24/533508/Pa/22584) (PIC)**
2. **Anders Emmanuel Tan (24/541351/Pa/22964)**
3. **Azhar Maulana (24/533487/Pa/22582)**
4. **Evan Razzan Adytaputra (24/545257/PA/23166)**

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

The knowledge graph is dynamic and grows with every new article scraped.

* **Live Statistics:** You can get a live count of the total triples in the graph by accessing the API's status endpoint:
    `GET http://localhost:8000/`

* **Automated Strategic Reports:**
    The system includes an automated analyst that evaluates the graph daily. It aggregates data on all threat actors and their tools to identify global trends.
    * **Access:** Reports are generated automatically in the `reports/` folder.
    * **Content:** Each report contains a "Strategic Threat Landscape Assessment," highlighting key active groups and tooling trends.

* **Graph Statistics (Evaluation):** We can run SPARQL queries to get statistics on the constructed graph.

    **Query to count entities by type:**

    ```sparql
    PREFIX stix: [http://docs.oasis-open.org/cti/ns/stix#](http://docs.oasis-open.org/cti/ns/stix#)
    PREFIX rdfs: [http://www.w3.org/2000/01/rdf-schema#](http://www.w3.org/2000/01/rdf-schema#)

    SELECT (str(?type) as ?EntityType) (COUNT(DISTINCT ?s) as ?Count)
    WHERE {
      GRAPH [http://group2.org/cskg](http://group2.org/cskg) {
        ?s a ?type .
        # Filter for only STIX types
        FILTER(CONTAINS(str(?type), "stix"))
      }
    }
    GROUP BY ?type
    ORDER BY DESC(?Count)
    ```

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

Here are 3 example use cases for our constructed KG, with example queries.

### Use Case 1: Threat Actor Profiling

**Question:** "What malware and attack patterns does the threat actor 'Konni' use, based on recent reports?"

```sparql
PREFIX cskg: [http://group2.org/cskg/](http://group2.org/cskg/)
PREFIX stix: [http://docs.oasis-open.org/cti/ns/stix#](http://docs.oasis-open.org/cti/ns/stix#)
PREFIX rdfs: [http://www.w3.org/2000/01/rdf-schema#](http://www.w3.org/2000/01/rdf-schema#)

SELECT DISTINCT ?malware_label ?pattern_label
WHERE {
  GRAPH [http://group2.org/cskg](http://group2.org/cskg) {
    # Find the Konni threat actor
    ?actor a stix:ThreatActor ;
           rdfs:label "Konni" .
    
    # Find malware it uses
    OPTIONAL {
      ?actor stix:uses ?malware .
      ?malware a stix:Malware ;
               rdfs:label ?malware_label .
    }
    
    # Find attack patterns it uses
    OPTIONAL {
      ?actor stix:uses ?pattern .
      ?pattern a stix:AttackPattern ;
               rdfs:label ?pattern_label .
    }
  }
}
```

### Use Case 2: Vulnerability Impact Assessment

**Question:** "We are vulnerable to 'CVE-2025-12480'. Which threat actors are actively exploiting it?"

```sparql
PREFIX cskg: [http://group2.org/cskg/](http://group2.org/cskg/)
PREFIX stix: [http://docs.oasis-open.org/cti/ns/stix#](http://docs.oasis-open.org/cti/ns/stix#)
PREFIX rdfs: [http://www.w3.org/2000/01/rdf-schema#](http://www.w3.org/2000/01/rdf-schema#)
PREFIX sepses: [https://w3id.org/sepses/resource/cve/](https://w3id.org/sepses/resource/cve/)

SELECT DISTINCT ?actor_label
WHERE {
  GRAPH [http://group2.org/cskg](http://group2.org/cskg) {
    # Find the CVE (using its linked SEPSES URI)
    BIND(sepses:CVE-2025-12480 AS ?cve)
    
    ?cve a stix:Vulnerability .
    
    # Find any threat actor that exploits it
    ?actor stix:exploits ?cve ;
           a stix:ThreatActor ;
           rdfs:label ?actor_label .
  }
}
```

### Use Case 3: Incident Response & Triage

**Question:** "We found the indicator 'GlassWorm' in our logs. What is it, and what reports mention it?"

```sparql
PREFIX cskg: [http://group2.org/cskg/](http://group2.org/cskg/)
PREFIX stix: [http://docs.oasis-open.org/cti/ns/stix#](http://docs.oasis-open.org/cti/ns/stix#)
PREFIX rdfs: [http://www.w3.org/2000/01/rdf-schema#](http://www.w3.org/2000/01/rdf-schema#)

SELECT ?entity_label ?entity_type ?report_url
WHERE {
  GRAPH [http://group2.org/cskg](http://group2.org/cskg) {
    # Find the entity by its label
    ?entity rdfs:label "GlassWorm" ;
            a ?entity_type ;
            rdfs:label ?entity_label .
    
    # Find the report that mentions it
    ?report stix:mentions ?entity ;
            a stix:Report .
    
    # Get the URL of the report
    BIND(IRI(str(?report)) as ?report_url)
    
    # Filter for only STIX types
    FILTER(CONTAINS(str(?entity_type), "stix"))
  }
}
```

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
