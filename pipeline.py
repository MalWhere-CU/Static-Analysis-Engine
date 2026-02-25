import os
import time
from detection.packer_detection import detect_packer
from reports.yara_report_generator import YaraReportGenerator
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from dotenv import load_dotenv

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DB_PATH = os.getenv("DB_PATH")


class StaticPipeline:
    def __init__(self, file_path: str, yara_ai_explainer: bool =False):
        self.file_path = file_path
        self.yara_engine = YaraEngine(DB_PATH)
        self.yara_reporter = YaraReportGenerator(self.file_path, yara_ai_explainer)

    def process_file(self) -> dict:
        start_time = time.time()

        result = {
            "file": self.file_path,
            "packed": False,
            "unpacked": False,
            "yara_matches": [],
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

            result["yara_matches"] = matches
            
            
            if matches:
                result["status"] = "malicious"
                self.yara_reporter.add_yara_matches(matches)
                result["report_data"] = self.yara_reporter.generate_json()

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        UnpackFile.cleanup(unpacked_path) if result["unpacked"] else None

        print(result)
        return result["report_data"]
