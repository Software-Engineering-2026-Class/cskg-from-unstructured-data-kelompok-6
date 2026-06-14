# Changelog

All notable changes to the Cybersecurity Knowledge Graph (CSKG) project (Group 6) are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to Semantic Versioning.

---

## [1.4.0] - 2026-06-14
### Added
- Created `[.env.example](.env.example)` to guide workspace deployment configurations securely.
- Added pipeline architecture diagram (`docs/architecture_diagram.svg`) reference to `[README.md](README.md)`.
- Integrated a sample pipeline input/output section in `[README.md](README.md)` for clear visual validation.

### Changed
- Refactored `[pipeline/build_kg.py](pipeline/build_kg.py)` to use a helper function `resolve_entity_uri()` that ensures CVE and CWE relationships correctly target external `SEPSES` namespace URIs (e.g., `sepses:CVE-xxxx-xxxx`) rather than fallback local `cskg:` URIs.
- Standardized and aligned Use Case 2 and 3 queries across `[README.md](README.md)`, `[sparql_demos.py](sparql_demos.py)`, and `[sparql_demo_ui.html](sparql_demo_ui.html)`.
- Improved repository security by moving database secrets to `[.env.example](.env.example)` and ensuring local `.env` is untracked via `[.gitignore](.gitignore)`.

### Fixed
- Fixed Virtuoso SPARQL compiler syntax error **SP031** (*"Variable 'actor' is used in subexpressions of the query but not assigned"*) in Use Case 3 by formally assigning the `?actor` variable inside the `OPTIONAL` block via a triple pattern.
- Fixed query join mapping issue where Use Case 2 yielded empty results due to the database relationship URI namespace mismatch.

---

## [1.3.0] - 2026-06-03
### Added
- Added comprehensive contribution guidelines to `[README.md](README.md)` outlining issues, changes, adding sources, and custom queries.
- Included sample pipeline output files `output_extracted.json`, `output_kg.ttl`, `output_raw.json`, and added `show_pipeline_output.py` for visual pipeline verification.
- Documented scenario explanations involving threat actors, vulnerabilities, and incident response timelines.

### Fixed
- Refactored daily evaluation script `[pipeline/graph_eval.py](pipeline/graph_eval.py)` for reliability.
- Corrected markdown table alignments and details of member contribution logs.

---

## [1.2.0] - 2026-05-31
### Added
- Developed CLI demo query client `[sparql_demos.py](sparql_demos.py)` to execute and print the three scenario-based queries directly.
- Created `[sparql_demo_ui.html](sparql_demo_ui.html)`, a dark-themed, glassmorphic interactive web dashboard to run SPARQL queries against the live Virtuoso instance.
- Formulated `[ontology/cskg_ontology.ttl](ontology/cskg_ontology.ttl)` containing the formal ontology definitions for the CSKG.
- Integrated a FastAPI query endpoint `/query` in the backend API server.
- Added live result tables and CLI execution screenshots to the `[README.md](README.md)`.

### Fixed
- Resolved SPARQL query syntax bugs and variable alignment errors.

---

## [1.1.0] - 2026-05-25
### Added
- Created `[kg_stats.py](kg_stats.py)` to calculate triple counts, entity distributions, quality overview metrics, and output visual graphs.
- Created `[kg_dashboard.html](kg_dashboard.html)`, an interactive HTML dashboard utilizing Chart.js to render real-time statistics from `kg_report.json`.
- Configured secondary data feed `CIRCL CVE` for vulnerability ingestion.
- Upgraded the LangChain Gemini extraction model definition to use `gemini-3.1-flash-lite`.
- Introduced entity duplication resolution and temporal logging properties in `[pipeline/build_kg.py](pipeline/build_kg.py)`.

---

## [1.0.0] - 2025-11-21
### Added
- Initial pipeline architecture and setup.
- Implemented scraper (`[pipeline/scraper.py](pipeline/scraper.py)`) supporting RSS feeds and API endpoints.
- Implemented LangChain extractor (`[pipeline/extractor.py](pipeline/extractor.py)`) with Gemini LLM model and Pydantic schema parsing.
- Created graph builder (`[pipeline/build_kg.py](pipeline/build_kg.py)`) to generate turtle triples conforming to the STIX ontology.
- Configured Redis container as a message bus/queue and OpenLink Virtuoso container as a triple store database.
- Created background workers (`producer_worker`, `scraper_worker`, `extractor_worker`, `builder_worker`) to process incoming articles continuously.
- Implemented daily evaluation (`[pipeline/graph_eval.py](pipeline/graph_eval.py)`) and dump script (`[server/cskg_dump.py](server/cskg_dump.py)`) saving to `cskg_full_dump.ttl`.
