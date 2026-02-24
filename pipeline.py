import os
import time
from detection.packer_detection import detect_packer
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from config import DB_PATH


class ScanPipeline:
    def __init__(self):
        self.yara_engine = YaraEngine(DB_PATH)

    def process_file(self, file_path: str) -> dict:
        start_time = time.time()

        result = {
            "file": file_path,
            "packed": False,
            "unpacked": False,
            "yara_matches": [],
            "status": "benign",
            "error": None,
            "scan_time": 0
        }

        try:
            packer_info = detect_packer(file_path)

            if packer_info.get("die_match") or packer_info.get("section_match") or packer_info.get("high_entropy"):
                result["packed"] = True

                unpacked_path = UnpackFile.unpack(file_path) # to be extended to support multiple unpacking methods
                print(unpacked_path)
                if unpacked_path and os.path.exists(unpacked_path):
                    result["unpacked"] = True
                    matches = self.yara_engine.scan_file(unpacked_path)
                else:
                    matches = self.yara_engine.scan_file(file_path)
            else:
                matches = self.yara_engine.scan_file(file_path)

            result["yara_matches"] = matches
            

            if matches:
                result["status"] = "malicious"

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        UnpackFile.cleanup(unpacked_path) if result["unpacked"] else None

        return result
