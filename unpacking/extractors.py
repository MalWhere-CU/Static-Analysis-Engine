
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
        # 1. Handle Docker container path fallback cleanly
        script_path = "/opt/pyinstxtractor.py" if os.path.exists("/opt/pyinstxtractor.py") else "pyinstxtractor.py"
        
        # 2. Extract just the filename, since we'll change the execution directory context
        filename = os.path.basename(file_path)
        cmd = ["python", script_path, filename]
        
        expected_output_dir = f"{file_path}_extracted"
        
        try:
            # 3. Resolve the directory where the sample lives
            sample_dir = os.path.dirname(file_path) or "."
            
            # 4. Run the subprocess INSIDE the sample directory (cwd)
            # This forces pyinstxtractor to drop its output folders exactly where we expect them
            res = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                cwd=sample_dir
            )
            
            if os.path.exists(expected_output_dir):
                return True, expected_output_dir
                
            # Fallback: Capture stdout if stderr is blank (pyinstxtractor often prints logs to stdout)
            error_msg = res.stderr.strip() or res.stdout.strip()
            return False, f"PyInstaller Extraction Failed: {error_msg}"
            
        except FileNotFoundError:
            return False, f"Python or extractor script not found at {script_path}."

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