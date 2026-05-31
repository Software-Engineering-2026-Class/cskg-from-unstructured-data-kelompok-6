from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import (
    BaseModel,
    Field,
)
import uvicorn
from SPARQLWrapper import SPARQLWrapper, JSON
from typing import Any

# --- Configuration ---
SPARQL_ENDPOINT = "http://virtuoso:8890/sparql"

# --- Initialize FastAPI ---
app = FastAPI(
    title="Cybersecurity Knowledge Graph API",
    description="Query a LIVE CSKG running on Virtuoso.",
)

# --- CORS Middleware ---
# Allows requests from local HTML files (file:// origin = "null")
# and localhost dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- API Models ---
class QueryRequest(BaseModel):
    query: str = Field(
        ...,
        json_schema_extra={"example": "SELECT ?s ?p ?o WHERE { ?s ?p ?o . } LIMIT 10"},
    )


def get_sparql_connection():
    """Configures the SPARQLWrapper for Virtuoso."""
    sparql = SPARQLWrapper(SPARQL_ENDPOINT)
    sparql.setReturnFormat(JSON)
    return sparql


@app.get("/", summary="Check API and graph status")
def get_status():
    """Checks if the API is running and pings the Virtuoso DB."""
    try:
        sparql = get_sparql_connection()
        sparql.setQuery("SELECT (COUNT(*) as ?triples) WHERE { ?s ?p ?o }")

        results: Any = sparql.query().convert()

        # This line will now pass type-checking
        triples_count = results["results"]["bindings"][0]["triples"]["value"]

        return {
            "status": "online",
            "graph_db_backend": "Virtuoso",
            "sparql_endpoint": SPARQL_ENDPOINT,
            "total_triples": int(triples_count),
        }
    except Exception as e:
        return {"status": "error", "db_connection_error": str(e)}


@app.post("/query", summary="Execute a SPARQL query")
def query_graph(request: QueryRequest = Body(...)):
    """Executes a raw SPARQL query against the Virtuoso database."""
    try:
        sparql = get_sparql_connection()
        sparql.setQuery(request.query)

        # --- CHANGE 4: Add the same type hint here ---
        results: Any = sparql.query().convert()

        # These lines will now pass type-checking
        variables = results.get("head", {}).get("vars", [])
        output = []
        for binding in results.get("results", {}).get("bindings", []):
            row_dict = {}
            for var in variables:
                row_dict[var] = binding.get(var, {}).get("value")
            output.append(row_dict)

        return {"variables": variables, "results": output}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query failed: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
