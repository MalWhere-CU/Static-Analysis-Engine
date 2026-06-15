import os
import time
from detection.packer_detection import detect_packer
from models.malwhere_malconv import MalWhereMalConv
from reports_generation.yara_report_generator import YaraReportGenerator
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from yara_engine.postgres import SessionLocal, init_db
from yara_engine.models import GeneratedRule
from yara_engine.db import get_enabled_rules, get_generated_rules
from xai.pipeline import XAIPipeline
from yara_rules_generation.generate_yara_rules import generate_and_save_rule
from dotenv import load_dotenv

load_dotenv()

class StaticPipeline:
    def __init__(self, file_path: str,
                 yara_ai_explainer: bool = False,
                 use_xai: bool = True,
                 xai_method: str = 'deeplift'):
        self.file_path = os.path.abspath(file_path)
        self.imported_yara_engine = self._init_yara_engine(get_enabled_rules())
        self.generated_yara_engine = self._init_yara_engine(get_generated_rules())
        self.yara_reporter = YaraReportGenerator(self.file_path, yara_ai_explainer)
        self.malconv_detector = MalWhereMalConv()
        self.use_xai = use_xai
        self.xai_method = xai_method
        self.xai_pipeline = XAIPipeline(
                model=self.malconv_detector.model,
                method=self.xai_method,
                top_k=10
            )

    def _init_yara_engine(self, rules_list: list[str]) -> YaraEngine | None:
        """Helper to initialize YaraEngine safely and consistently."""
        if not rules_list:
            return None
            
        rules_text = "\n".join(rules_list)
        if not rules_text.strip():
            return None
            
        try:
            return YaraEngine(rules_text)
        except Exception as e:
            print(f"Failed to initialize YaraEngine: {e}")
            return None
        
    def process_file(self) -> dict:
        start_time = time.time()

        result = {
            "file": self.file_path,
            "packed": False,
            "unpacked": False,
            "matched": False,
            "match_source": None,
            "yara_matches": [],
            "malconv_result": None,
            "xai_result": None,
            "generated_rule": None,
            "status": "benign",
            "error": None,
        }

        unpacked_path = None
        temp_folder = None

        try:
            packer_info = detect_packer(self.file_path)

            if packer_info.get("die_match") or packer_info.get("section_match") or packer_info.get("high_entropy"):
                result["packed"] = True
                unpacked_path, temp_folder = UnpackFile.unpack(self.file_path)
                if unpacked_path and os.path.exists(unpacked_path):
                    result["unpacked"] = True

            file_to_scan = unpacked_path if result["unpacked"] else self.file_path

            imported_rules_matches = self.imported_yara_engine.scan_file(file_to_scan) if self.imported_yara_engine else None
            generated_rules_matches = self.generated_yara_engine.scan_file(file_to_scan) if self.generated_yara_engine else None
            if imported_rules_matches or generated_rules_matches: 
                result["matched"] = True
                result["status"] = "malicious"

                if imported_rules_matches:
                    result["match_source"] = "rules"
                    result["yara_matches"] = [m.rule for m in imported_rules_matches]
                    self.yara_reporter.add_yara_matches(imported_rules_matches)

                if generated_rules_matches: 
                    result["match_source"] = "generated_rules"
                    result["yara_matches"] = [m.rule for m in generated_rules_matches]
                    self.yara_reporter.add_yara_matches(generated_rules_matches)

                result.update(self.yara_reporter.get_report_data())
            else:
                malconv_result = self.malconv_detector.predict(file_to_scan)
                result["malconv_result"] = malconv_result

                if malconv_result["prediction"] == "malicious":
                    result["matched"] = True
                    result["match_source"] = "malconv"
                    result["status"] = "malicious"

                    if self.use_xai:
                        analysis = self.xai_pipeline.analyze_file(file_to_scan, target_class=None)
                        xai_result = self.xai_pipeline.to_json(analysis)
                        result["xai_result"] = xai_result

                        if "error" not in xai_result:
                            rule_name = generate_and_save_rule(xai_result)
                            result["generated_rule"] = rule_name
                else:
                    result["matched"] = False
                    result["status"] = "benign"

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        if temp_folder:
            UnpackFile.cleanup(temp_folder)

        return result