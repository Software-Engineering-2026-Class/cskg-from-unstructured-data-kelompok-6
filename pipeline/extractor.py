import os
from typing import List, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import PydanticOutputParser


class EntityRelation(BaseModel):
    subject: str = Field(description="The primary entity, e.g., 'APT29'")
    relationship: str = Field(
        description="The action or link, e.g., 'uses', 'targets', 'attributed_to'"
    )
    object: str = Field(
        description="The secondary entity, e.g., 'Triton Malware', 'CVE-2023-1234'"
    )


class CyberEntities(BaseModel):
    threat_actors: Optional[List[str]] = Field(
        description="All threat actor groups or individuals"
    )
    malware: Optional[List[str]] = Field(
        description="All malware, ransomware, or tools"
    )
    vulnerabilities: Optional[List[str]] = Field(
        description="All CVEs or named vulnerabilities"
    )
    indicators: Optional[List[str]] = Field(
        description="All IPs, domains, or file hashes"
    )
    attack_patterns: Optional[List[str]] = Field(
        description="All attack techniques, e.g., 'Phishing'"
    )
    relations: Optional[List[EntityRelation]] = Field(
        description="All identified relationships between entities"
    )


def get_extraction_chain():
    load_dotenv()
    gemini_key = os.getenv("GOOGLE_API_KEY")

    if gemini_key:
        os.environ["GOOGLE_API_KEY"] = gemini_key
    else:
        print("ERROR: GOOGLE_API_KEY not found in .env file.")
        print("Please ensure your .env file is correct.")
        return

    llm = ChatGoogleGenerativeAI(model="gemini-3.1-flash-lite")
    # Define the output parser based on our Pydantic model
    parser = PydanticOutputParser(pydantic_object=CyberEntities)

    # relationship from the stix ontology
    ALLOWED_RELATIONSHIPS = [
        "uses",
        "targets",
        "exploits",
        "mitigates",
        "attributed_to",
        "variant_of",
        "located_in",
        "impersonates",
        "reports",
        "patched",
        "resolved",
        "disrupted",
        "aligned_with",
        "observes",
        "has_similarities_with",
        "propagated_via",
    ]

    new_template = """
    Analyze the following cybersecurity article. Extract all key entities and their relationships.
    
    When extracting a relationship, you MUST use one of the following verbs for the 'relationship' field:
    {allowed_relationships}

    **IMPORTANT: If you do not find any entities for a specific category (e.g., 'threat_actors', 'malware'), you MUST return an empty list `[]` for that category. Do NOT return a list containing `null` or `None`.**
    
    {format_instructions}
    
    Article Text:
    "{article_text}"
    """

    prompt = PromptTemplate(
        template=new_template,
        input_variables=["article_text"],
        partial_variables={
            "format_instructions": parser.get_format_instructions(),
            # Pass our allowed list into the prompt
            "allowed_relationships": ", ".join(ALLOWED_RELATIONSHIPS),
        },
    )

    chain = prompt | llm | parser
    return chain
