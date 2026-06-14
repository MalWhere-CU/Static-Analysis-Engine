import os
import shutil
import subprocess
from pathlib import Path

class ExtractorBase:
    """Base template for all extractors"""
    def execute(self, file_path: str) -> tuple[bool, str]:
        raise NotImplementedError

class UPXExtractor(ExtractorBase):
    def execute(self, file_path: str) -> tuple[bool, str]:
        output_path = f"{file_path}_unpacked.exe"
        cmd = ["upx", "-d", "-o", output_path, file_path]
        
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0 and os.path.exists(output_path):
                return True, output_path
            return False, f"UPX Failed: {res.stderr}"
        except FileNotFoundError:
            return False, "UPX tool not found in PATH."

class De4DotExtractor(ExtractorBase):
    def execute(self, file_path: str) -> tuple[bool, str]:
        output_path = f"{file_path}_deobfuscated.exe"
        
        # Check if running inside Docker/Linux or fallback to global Windows binary name
        if os.path.exists("/opt/de4dot/de4dot.dll"):
            # Linux .NET Core call structure inside your Docker container
            cmd = ["dotnet", "/opt/de4dot/de4dot.dll", file_path, "-o", output_path]
        else:
            # Fallback for local Windows execution
            cmd = ["de4dot", file_path, "-o", output_path]
        
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "ERROR" not in res.stdout and os.path.exists(output_path):
                return True, output_path
            return False, f"de4dot Failed: {res.stdout or res.stderr}"
        except FileNotFoundError:
            return False, "de4dot/dotnet execution environment not detected."

class PyInstExtractor(ExtractorBase):
    def execute(self, file_path: str) -> tuple[bool, str]:
        # pyinstxtractor.py must be downloaded and available in the same directory or PATH
        cmd = ["python", "pyinstxtractor.py", file_path]
        expected_output_dir = f"{file_path}_extracted"
        
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if os.path.exists(expected_output_dir):
                return True, expected_output_dir
            return False, f"PyInstaller Extraction Failed: {res.stderr}"
        except FileNotFoundError:
            return False, "Python or pyinstxtractor.py not found."

class ArchiveExtractor(ExtractorBase):
    def execute(self, file_path: str) -> tuple[bool, str]:
        output_dir = f"{file_path}_dump"
        # 7z x <archive> -o<output_dir> -y (yes to all prompts)
        cmd = ["7z", "x", file_path, f"-o{output_dir}", "-y"]
        
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0 and os.path.exists(output_dir):
                return True, output_dir
            return False, f"7z Failed: {res.stderr}"
        except FileNotFoundError:
            return False, "7z tool not found in PATH."