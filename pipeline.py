import os
import time
from detection.packer_detection import detect_packer
from detection.malconv_detection import MalConvDetector
from reports.yara_report_generator import YaraReportGenerator
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH")


class StaticPipeline:
    def __init__(self, file_path: str,
                 yara_ai_explainer: bool = False,
                 use_xai: bool = False,
                 xai_explainer: bool = False,
                 xai_method: str = 'deeplift'):
        """
        Args:
            file_path: Path to the file to analyze.
            yara_ai_explainer: Enable LLM explanation for YARA rule matches.
            use_xai: Enable XAI attribution analysis on MalConv predictions.
            xai_explainer: Enable LLM explanation for XAI attribution results.
            xai_method: XAI method to use ('deeplift', 'lime', etc.).
        """
        self.file_path = os.path.abspath(file_path)
        self.yara_engine = YaraEngine(DB_PATH)
        self.yara_reporter = YaraReportGenerator(self.file_path, yara_ai_explainer)
        self.malconv_detector = MalConvDetector()
        self.use_xai = use_xai
        self.xai_explainer = xai_explainer & use_xai  # Only enable explainer if XAI is enabled
        self.xai_method = xai_method

    def process_file(self) -> dict:
        start_time = time.time()

        result = {
            "file": self.file_path,
            "packed": False,
            "unpacked": False,
            "yara_matches": [],
            "malconv_result": None,
            "xai_result": None,
            "status": "benign",
            "error": None,
            "scan_time": 0,
            "report_data": None
        }

        try:
            packer_info = detect_packer(self.file_path)

            if packer_info.get("die_match") or packer_info.get("section_match") or packer_info.get("high_entropy"):
                result["packed"] = True

                unpacked_path = UnpackFile.unpack(self.file_path) # to be extended to support multiple unpacking methods
                print(unpacked_path)
                if unpacked_path and os.path.exists(unpacked_path):
                    result["unpacked"] = True
                    matches = self.yara_engine.scan_file(unpacked_path)
                else:
                    matches = self.yara_engine.scan_file(self.file_path)
            else:
                matches = self.yara_engine.scan_file(self.file_path)

            #TODO: when UPX is available delete the below line and uncomment the commented code and vice versa
            # matches = self.yara_engine.scan_file(self.file_path)
            result["yara_matches"] = [m.rule for m in matches]
            
            
            if matches:
                result["status"] = "malicious"
                self.yara_reporter.add_yara_matches(matches)

                # Save YARA report to yara_reports/<filename>_yara_report.json
                reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_reports")
                os.makedirs(reports_dir, exist_ok=True)
                file_stem = os.path.splitext(os.path.basename(self.file_path))[0]
                report_path = os.path.join(reports_dir, f"{file_stem}_yara_report.json")
                result["report_data"] = self.yara_reporter.generate_json(output_path=report_path)
            else:
                # No YARA matches, use MalConv
                file_to_scan = unpacked_path if result["unpacked"] and os.path.exists(unpacked_path) else self.file_path
                malconv_result = self.malconv_detector.predict(file_to_scan)
                result["malconv_result"] = malconv_result
                if malconv_result["prediction"] == "malicious":
                    result["status"] = "malicious"

                # Run XAI if enabled and MalConv was used
                if self.use_xai:
                    result["xai_result"] = self._run_xai(file_to_scan)

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        UnpackFile.cleanup(unpacked_path) if result["unpacked"] else None

        return result

    def _run_xai(self, file_path: str) -> dict:
        """Run XAI attribution analysis on the file."""
        try:
            from xai.pipeline import XAIPipeline

            pipeline = XAIPipeline(
                model=self.malconv_detector.model,
                method=self.xai_method,
                top_k=10,
                use_explainer=self.xai_explainer,
            )
            analysis = pipeline.analyze_file(file_path, target_class=None)
            return pipeline.to_json(analysis)
        except Exception as e:
            return {"error": f"XAI analysis failed: {str(e)}"}