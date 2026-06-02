from dotenv import load_dotenv
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate


def generate_brief(data, date_str):
    """
    Generates a strategic cybersecurity brief based on aggregated threat actor data.

    Parameters:
    - data (list/str): Aggregated graph data representing threat actor capabilities.
    - date_str (str): The current date string for the report.

    Returns:
    - str: The markdown-formatted report content, or None if generation failed.
    """
    print(f"[SUMMARY] Initiating LLM brief generation for date: {date_str}")
    load_dotenv()
    
    # Validation
    if not os.getenv("GOOGLE_API_KEY"):
        print("[SUMMARY] ERROR: GOOGLE_API_KEY environment variable is not set.")
        return None

    try:
        llm = ChatGoogleGenerativeAI(model="gemini-3.1-flash-lite")

        template = """
        You are a Strategic Cyber Intelligence Analyst. 
        Current Reporting Date: {date}
        
        Your task is to write a 'Comprehensive Threat Landscape Assessment' based on the aggregated knowledge in our graph.
        
        The data below represents the Known Capabilities of various Threat Actors tracked in our system.
        
        Please analyze this data to provide a strategic summary:
        1. **Key Threat Actors:** Which groups have the most diverse toolsets?
        2. **Tooling Trends:** Are there common tools being used across different actors?
        3. **Strategic Assessment:** Provide a high-level summary of the threat environment based on this data.
        
        Use a professional, authoritative tone. Do not focus on "today's events"—focus on the "overall state of the threat."
    
        Aggregated Graph Data:
        {graph_data}
        """

        prompt = PromptTemplate.from_template(template)
        chain = prompt | llm
        
        print("[SUMMARY] Dispatching request to Gemini model...")
        response = chain.invoke({"graph_data": data, "date": date_str})
        content = response.content
        
        # Handle cases where LangChain content blocks are returned as a list
        if isinstance(content, list):
            print("[SUMMARY] Parsing block-based LLM response list...")
            text_blocks = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_blocks.append(block.get("text", ""))
                elif isinstance(block, str):
                    text_blocks.append(block)
            content = "\n".join(text_blocks)
        
        if not content:
            print("[SUMMARY] WARNING: Received empty content from LLM.")
            return None
            
        print("[SUMMARY] Successfully generated intelligence brief.")
        return content

    except Exception as e:
        print(f"[SUMMARY] ERROR during LLM brief generation: {str(e)}")
        return None
