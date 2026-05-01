"""XAI LLM Explainer using Gemini via LangChain.

Takes XAI attribution results (regions, PE mappings, prediction) and generates
a human-friendly natural language interpretation using an LLM.
"""

import os
from typing import Dict, List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

load_dotenv()


class AttributionExplanation(BaseModel):
    """Structured output for XAI attribution explanation."""

    summary: str = Field(
        description="A 2-3 sentence high-level summary of what the model detected and why."
    )
    key_indicators: List[str] = Field(
        description="List of specific indicators found in the attributed regions "
                    "(e.g., suspicious sections, strings, imports, packing evidence)."
    )
    risk_assessment: str = Field(
        description="Brief risk assessment: what type of threat this might represent "
                    "based on the attribution evidence (e.g., packed malware, trojan, PUP)."
    )
    confidence_note: str = Field(
        description="Note on how confident the explanation is, given the model's "
                    "prediction confidence and the clarity of attributed regions."
    )


class XAIExplainer:
    """Generates human-readable explanations of XAI attribution results using Gemini."""

    def __init__(self, model_name: str = "gemini-2.5-flash"):
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment. Set it in .env file.")

        self.llm = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=0.3,
        )
        self.structured_llm = self.llm.with_structured_output(AttributionExplanation)

        self.prompt = ChatPromptTemplate.from_messages([
            ("system",
             "You are an expert malware analyst interpreting XAI (Explainable AI) attribution "
             "results from a deep learning malware classifier (MalConv2). "
             "The model classifies PE executables as malicious or benign by analyzing raw bytes. "
             "XAI methods attribute importance scores to byte regions, and these regions are "
             "mapped to PE structures (sections, strings, imports). "
             "Your job is to interpret these results in clear, actionable language for a "
             "security analyst."),
            ("human", "{input}"),
        ])

        self.chain = self.prompt | self.structured_llm

    def explain(self, analysis_result: Dict) -> AttributionExplanation:
        """
        Generate a structured explanation from an XAI analysis result.

        Args:
            analysis_result: The dict returned by XAIPipeline.to_json()

        Returns:
            AttributionExplanation with structured fields.
        """
        input_text = self._format_input(analysis_result)
        return self.chain.invoke({"input": input_text})

    def _format_input(self, result: Dict) -> str:
        """Format the analysis result into a prompt-friendly string."""
        lines = []

        file_name = os.path.basename(result.get("file", "unknown"))
        file_size = result.get("file_size", 0)
        method = result.get("method", "unknown")
        pred_class = result.get("predicted_class", "unknown")
        confidence = result.get("confidence", 0.0)

        lines.append(f"File: {file_name} ({file_size:,} bytes)")
        lines.append(f"XAI Method: {method}")
        lines.append(f"Prediction: {pred_class} (confidence: {confidence:.4f})")
        lines.append("")

        # Top regions
        regions = result.get("top_regions", [])
        if regions:
            lines.append("Top Attribution Regions:")
            for i, r in enumerate(regions[:10]):
                lines.append(
                    f"  #{i+1}: offset 0x{r['start_offset']:06X}-0x{r['end_offset']:06X} "
                    f"score={r['score']:.6f} direction={r['direction']}"
                )
            lines.append("")

        # PE mapping
        pe_mapping = result.get("pe_mapping")
        if pe_mapping and isinstance(pe_mapping, dict):
            region_mappings = pe_mapping.get("region_mappings", [])
            if region_mappings:
                lines.append("PE Structure Mapping:")
                for mapping in region_mappings[:10]:
                    sec = mapping.get("section")
                    sec_name = sec["name"] if sec else "UNKNOWN"
                    offset = mapping.get("start_offset", 0)
                    entropy = sec.get("entropy", 0) if sec else 0
                    lines.append(
                        f"  0x{offset:06X}: section={sec_name} (entropy={entropy:.2f})"
                    )
                    for s in mapping.get("strings", [])[:3]:
                        lines.append(f"    STRING: {s['value'][:80]!r}")
                    for imp in mapping.get("imports", [])[:3]:
                        lines.append(f"    IMPORT: {imp['dll']}!{imp['function']}")

            # File info
            file_info = pe_mapping.get("file_info", {})
            if file_info:
                sections = file_info.get("sections", [])
                if sections:
                    lines.append("")
                    lines.append("PE Sections Overview:")
                    for s in sections:
                        lines.append(
                            f"  {s['name']}: size={s['raw_size']:,} entropy={s.get('entropy', 0):.2f}"
                        )

        return "\n".join(lines)
