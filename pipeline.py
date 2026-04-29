import os
import time
from detection.packer_detection import detect_packer
from detection.malconv_detection import MalConvDetector
from reports.yara_report_generator import YaraReportGenerator
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from dotenv import load_dotenv

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DB_PATH = os.getenv("DB_PATH")


class StaticPipeline:
    def __init__(self, file_path: str, yara_ai_explainer: bool =False):
        self.file_path = os.path.abspath(file_path)
        self.yara_engine = YaraEngine(DB_PATH)
        self.yara_reporter = YaraReportGenerator(self.file_path, yara_ai_explainer)
        self.malconv_detector = MalConvDetector()

    def process_file(self) -> dict:
        start_time = time.time()

        result = {
            "file": self.file_path,
            "packed": False,
            "unpacked": False,
            "yara_matches": [],
            "malconv_result": None,
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
                result["report_data"] = self.yara_reporter.generate_json()
            else:
                # No YARA matches, use MalConv
                file_to_scan = unpacked_path if result["unpacked"] and os.path.exists(unpacked_path) else self.file_path
                malconv_result = self.malconv_detector.predict(file_to_scan)
                result["malconv_result"] = malconv_result
                if malconv_result["prediction"] == "malicious":
                    result["status"] = "malicious"

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        UnpackFile.cleanup(unpacked_path) if result["unpacked"] else None

        print(result)
        return result