import os
from typing import List

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

from caching.redis_explainer_caching import YaraExplainerRedisCache

load_dotenv()


class YaraExplanation(BaseModel):
    """Structured output for YARA rule explanation."""

    summary: str = Field(
        description="A 2-3 sentence high-level summary of what the matched YARA rules indicate "
                    "about the file's malicious capabilities."
    )
    capabilities: List[str] = Field(
        description="List of specific malware capabilities or behaviors detected by the rules "
                    "(e.g., keylogging, C2 communication, privilege escalation)."
    )
    threat_classification: str = Field(
        description="Classification of the threat type (e.g., Trojan, RAT, Ransomware, "
                    "APT toolkit, PUP, Exploit kit)."
    )
    severity: str = Field(
        description="Severity level: critical, high, medium, or low — based on the "
                    "combined indicators from matched rules."
    )
    recommended_actions: List[str] = Field(
        description="List of recommended response actions for a security analyst "
                    "(e.g., isolate host, memory forensics, block IOCs)."
    )


class YaraRuleExplainer:
    def __init__(self, yara_rules: list):
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment. Set it in .env file.")

        self.rules_context = "\n---\n".join(yara_rules)
        self.cache = YaraExplainerRedisCache()

        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            google_api_key=api_key,
            temperature=0.3,
        )
        structured_llm = llm.with_structured_output(YaraExplanation)

        prompt = ChatPromptTemplate.from_messages([
            ("system",
             "You are an expert Malware Researcher. You analyze YARA rule matches to explain "
             "what a detected malware does. You examine the rules' strings, conditions, and "
             "metadata to provide a consolidated, actionable report for security analysts."),
            ("human", "{input}"),
        ])

        self.chain = prompt | structured_llm

    def explain_rule(self) -> str:
        if not self.rules_context or len(self.rules_context.strip()) == 0:
            return "No YARA rules matched"

        try:
            cached_result = self.cache.get_explanation(self.rules_context)
            if cached_result:
                return f"{cached_result}"
        except Exception as e:
            print(f"[!] Error accessing cache: {e}")

        prompt_input = (
            "I have a file that matched the following YARA rules. "
            "Analyze the rules' strings, conditions, and metadata to explain "
            "exactly what this malware does.\n\n"
            f"YARA RULES:\n{self.rules_context}\n\n"
            "Provide a consolidated report explaining the combined capabilities detected."
        )

        try:
            result: YaraExplanation = self.chain.invoke({"input": prompt_input})

            explanation = (
                f"Summary: {result.summary} "
                f"Threat: {result.threat_classification} (Severity: {result.severity}) "
                f"Capabilities: " + ", ".join(c for c in result.capabilities) + ". "
                f"Recommended Actions: " + " ".join(a for a in result.recommended_actions)
            )
            
            try:
                self.cache.set_explanation(self.rules_context, explanation)
            except Exception as e:
                return f"[CACHING] Error while caching explanation {e}"

            return explanation
        except Exception as e:
            return f"Error generating AI explanation: {e}"
