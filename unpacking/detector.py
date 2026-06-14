import os
import math
import die  

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
            raw_scan = die.scan_file(
                file_path, 
                die.ScanFlags.RESULT_AS_JSON, 
                str(die.database_path)
            )
            
            
            # Stringifying the JSON payload allows us to search the full detailed tags
            scan_str = str(raw_scan).lower()
            result["die_signature"] = scan_str


            # 1. Native Compressors
            if "upx" in scan_str:
                result.update({"is_packed": True, "category": "UPX"})
            elif "mpress" in scan_str or "aspack" in scan_str:
                result.update({"is_packed": True, "category": "Bypass_Native"})
                
            # 2. Python Compilations
            elif "pyinstaller" in scan_str or "py2exe" in scan_str:
                result.update({"is_packed": True, "category": "PyInstaller"})

            # 3. .NET Obfuscators / Packers
            elif ".net" in scan_str and result["entropy"] > 6.0:
                result.update({"is_packed": True, "category": "DotNET"})

            # 4. Archives / Installers
            elif any(k in scan_str for k in ["sfx", "7z", "7-zip", "nullsoft", "inno setup", "winrar", "installer"]):
                result.update({"is_packed": True, "category": "Archive"})
                
            # Fallback: If it's a Linux ELF file masquerading as an .exe or named "dropper"    
            elif "elf64" in scan_str and (file_path.endswith('.exe') or "dropper" in file_path.lower()):
                result.update({"is_packed": True, "category": "Archive"})
            
            # 5. Heavy Protectors (To be bypassed in static, handled in dynamic)
            elif "themida" in scan_str or "vmprotect" in scan_str or "armadillo" in scan_str:
                result.update({"is_packed": True, "category": "Bypass_Protector"})
                
        except Exception as e:
            print(f"[!] DIE Detection Error: {e}")
            
        return result