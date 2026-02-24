import json
import os
from datetime import datetime
from utils.hashes import HashCalculator

class YaraReportGenerator:
    def __init__(self, file_path: str):
        self.file_path = file_path
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
            }
        }

    def add_yara_matches(self, matches:  list):
        """Processes YARA Match objects and extracts metadata for the report"""
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

    
    def generate_json(self, output_path: str = "report.json"):
        with open(output_path, "w") as f:
            json.dump(self.report_data, f, indent=4)
        return output_path