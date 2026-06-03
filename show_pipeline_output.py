"""
CVE Pipeline Visualization Script
This script demonstrates the end-to-end data transformation pipeline:
1. Stage 1: Fetching raw unstructured data from CIRCL CVE API.
2. Stage 2: Extracting structured entities using Gemini LLM.
3. Stage 3: Building Knowledge Graph triples (RDF/TTL).

Author: Antigravity AI (Senior Software Engineer)
Project: CSKG - Kelompok 6 MRPL
"""

import json
import os
import requests
import sys
from dotenv import load_dotenv

# Ensure the pipeline directory is in the path for imports
sys.path.append(os.path.join(os.getcwd(), "pipeline"))

try:
    from scraper import fetch_circl_cve
    from extractor import get_extraction_chain
    from build_kg import build_graph
except ImportError as e:
    print(f"Error importing pipeline modules: {e}")
    sys.exit(1)

def run_pipeline_demo():
    print("=== Starting CVE Pipeline Demo (CIRCL Source) ===\n")
    
    # --- STAGE 1: RAW DATA SCRAIPING ---
    print("[Stage 1] Fetching raw data from CIRCL...")
    # We fetch the last 1 CVE for demonstration
    circl_data_list = fetch_circl_cve(max_articles=1)
    
    if not circl_data_list:
        print("Error: Could not fetch data from CIRCL.")
        return

    raw_article = circl_data_list[0]
    
    # Save Raw Data
    with open("output_raw.json", "w", encoding="utf-8") as f:
        json.dump(raw_article, f, indent=4)
    print(f"-> Saved raw data to 'output_raw.json' (CVE ID: {raw_article['title']})")

    # --- STAGE 2: ENTITY EXTRACTION ---
    print("\n[Stage 2] Extracting entities using Gemini LLM...")
    
    chain = get_extraction_chain()
    if not chain:
        print("Error: Could not initialize extraction chain. Check your GOOGLE_API_KEY.")
        return
    
    try:
        # The chain expects 'article_text'
        extraction_result = chain.invoke({"article_text": raw_article["content"]})
        
        # Pydantic model to dict
        extracted_data = extraction_result.dict()
        
        # Save Extracted Data
        with open("output_extracted.json", "w", encoding="utf-8") as f:
            json.dump(extracted_data, f, indent=4)
        print("-> Saved extracted entities to 'output_extracted.json'")
    except Exception as e:
        print(f"Error during extraction: {e}")
        return

    # --- STAGE 3: KNOWLEDGE GRAPH CONSTRUCTION ---
    print("\n[Stage 3] Building Knowledge Graph (RDF)...")
    
    # The build_graph function expects a list of dictionaries with 'source_url', 'entities', and 'published'
    payload = [{
        "source_url": raw_article["link"],
        "entities": extracted_data,
        "published": raw_article["published"]
    }]
    
    try:
        g = build_graph(payload)
        
        # Serialize to Turtle format
        ttl_output = g.serialize(format="turtle")
        
        # Save KG Data
        with open("output_kg.ttl", "w", encoding="utf-8") as f:
            f.write(ttl_output)
        print("-> Saved Knowledge Graph to 'output_kg.ttl'")
    except Exception as e:
        print(f"Error during KG construction: {e}")
        return

    print("\n=== Pipeline Demo Complete ===")
    print("Files generated: output_raw.json, output_extracted.json, output_kg.ttl")

if __name__ == "__main__":
    run_pipeline_demo()
