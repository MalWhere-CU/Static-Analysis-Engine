import os
from detector import PackingDetector
from extractors import (
    UPXExtractor, 
    De4DotExtractor, 
    PyInstExtractor, 
    ArchiveExtractor
)

class StaticPreprocessingPipeline:
    def __init__(self):
        self.detector = PackingDetector()
        
        # Mapping categories from detector to their specific execution algorithms
        self.routes = {
            "UPX": UPXExtractor(),
            "DotNET": De4DotExtractor(),
            "PyInstaller": PyInstExtractor(),
            "Archive": ArchiveExtractor()
        }

    def process_file(self, file_path: str):
        print(f"[*] Starting Preprocessing on: {file_path}")
        
        # 1. Detect
        analysis = self.detector.analyze(file_path)
        print(f"    [>] Entropy: {analysis['entropy']}")
        print(f"    [>] Packed Status: {analysis['is_packed']}")
        print(f"    [>] Category: {analysis['category']}")

        # 2. Route & Execute
        category = analysis["category"]
        
        if not analysis["is_packed"] or category == "Clean":
            print("[+] File is clean/unpacked. Proceeding to static analysis directly.")
            return file_path

        if category in ["Bypass_Native", "Bypass_Protector"]:
            print(f"[!] Heavy Protector detected ({category}). Bypassing static extraction. Pushing to YARA & Dynamic VM.")
            return file_path

        # If we have an extractor for this category, run it
        if category in self.routes:
            extractor = self.routes[category]
            print(f"[*] Handing over to {extractor.__class__.__name__}...")
            
            success, output = extractor.execute(file_path)
            if success:
                print(f"[+] Successfully extracted/unpacked to: {output}")
                return output
            else:
                print(f"[-] Extraction failed. Error: {output}")
                return file_path
        else:
            print(f"[-] Unknown category '{category}'. No extractor configured.")
            return file_path

# ==========================================
# Run the Pipeline
# ==========================================
if __name__ == "__main__":
    # Ensure you have a test sample available to pass in here
    target_file = "sample_malware.exe" 
    
    pipeline = StaticPreprocessingPipeline()
    
    if os.path.exists(target_file):
        final_artifact = pipeline.process_file(target_file)
        print(f"\n[DONE] Send this to Static Analysis tools: {final_artifact}")
    else:
        print(f"[!] Target file '{target_file}' not found. Please provide a valid file.")