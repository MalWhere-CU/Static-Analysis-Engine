import json
import os
from datetime import datetime
from dotenv import load_dotenv
from caching.redis_explainer_caching import YaraExplainerRedisCache
from malware_explainer.yara_rule_explainer import YaraRuleExplainer
from utils.hashes import HashCalculator
from yara_engine.db import get_rule_text_by_name

load_dotenv()
DB_PATH = os.getenv("DB_PATH")

class YaraReportGenerator:
    def __init__(self, file_path: str, yara_ai_explainer: bool = False):
        self.file_path = file_path
        self.yara_ai_explainer = yara_ai_explainer
        self.report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "file_name": os.path.basename(file_path),
                "hashes": {
                    "md5": HashCalculator.calculate_md5_hash(file_path),
                    "sha256": HashCalculator.calculate_sha256_hash(file_path)
                }
            },
            "detections": [],
            "summary": {
                "total_matches": 0
            },
            "yara_ai_explainer": "",
        }

    def add_yara_matches(self, matches:  list):
        """Processes YARA Match objects and extracts metadata for the report"""
        matched_rule_texts = []
        for match in matches: 
            meta = match.meta
            detection = {
                "rule_name": match.rule,
                "description": meta.get("description", "No description provided"),
                "author": meta.get("author", "Unknown"),
                "date": meta.get("date", "Unknown"),
                "threat_level": meta.get("threat_level", "Not specified"),
                "score": meta.get("score", 0),
                "mitre_attck": meta.get("mitre_attck", "N/A"),
                "reference": meta.get("reference", ""),
                "tags": match.tags
            }
            self.report_data["detections"].append(detection)
            self.report_data["summary"]["total_matches"] += 1
            meta_string = json.dumps(match.meta, indent=2)
            matched_rule_texts.append(meta_string)

        if self.yara_ai_explainer:
            explainer = YaraRuleExplainer(yara_rules=matched_rule_texts)
            self.report_data["yara_ai_explainer"] = explainer.explain_rule()
        else:
            self.report_data["yara_ai_explainer"] = "YARA AI explaination not enabled for this report"

    
    def generate_json(self, output_path: str = "report.json"):
        with open(output_path, "w") as f:
            json.dump(self.report_data, f, indent=4)
        return output_path