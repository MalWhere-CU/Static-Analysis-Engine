import os
import math
import die  # pip install die-python

class PackingDetector:
    @staticmethod
    def calculate_entropy(file_path: str) -> float:
        if not os.path.exists(file_path):
            return 0.0
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def analyze(file_path: str) -> dict:
        """
        Uses Detect It Easy to classify the target into an actionable extraction category.
        """
        result = {
            "is_packed": False,
            "category": "Clean",
            "entropy": PackingDetector.calculate_entropy(file_path),
            "die_signature": ""
        }

        try:
            # Deep scan with Detect It Easy
            raw_scan = die.scan_file(file_path, die.ScanFlags.DEEP_SCAN)
            scan_str = str(raw_scan).lower()
            result["die_signature"] = scan_str

            # 1. Native Compressors
            if "upx" in scan_str:
                result.update({"is_packed": True, "category": "UPX"})
            elif "mpress" in scan_str or "aspack" in scan_str:
                # Modifying these is hard statically, tag for YARA bypass
                result.update({"is_packed": True, "category": "Bypass_Native"})
                
            # 2. Python Compilations
            elif "pyinstaller" in scan_str or "py2exe" in scan_str:
                result.update({"is_packed": True, "category": "PyInstaller"})

            # 3. .NET Obfuscators / Packers
            elif ".net" in scan_str and result["entropy"] > 6.0:
                # We flag high-entropy .NET files for deobfuscation
                result.update({"is_packed": True, "category": "DotNET"})

            # 4. Archives / Installers
            elif "sfx" in scan_str or "nullsoft" in scan_str or "inno setup" in scan_str:
                result.update({"is_packed": True, "category": "Archive"})
                
            # 5. Heavy Protectors (To be bypassed in static, handled in dynamic)
            elif "themida" in scan_str or "vmprotect" in scan_str or "armadillo" in scan_str:
                result.update({"is_packed": True, "category": "Bypass_Protector"})
                
        except Exception as e:
            result["die_signature"] = f"Error reading DIE: {e}"

        return result