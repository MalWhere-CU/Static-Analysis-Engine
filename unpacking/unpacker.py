import subprocess
import os
import tempfile
import shutil
from config import UPX_PATH

class UnpackFile:
    @staticmethod
    def unpack(file_path: str) -> str | None:
        """Uses UPX to unpack a sample"""
        temp_dir = tempfile.mkdtemp()
        input_path = os.path.join(temp_dir, file_path)
        unpacked_path = os.path.join(temp_dir, "putty_unpacked.exe")

        with open(file_path, "rb") as src, open(input_path, "wb") as dst:
            dst.write(src.read())

        try:
            cmd = [UPX_PATH, "-d", "-o", unpacked_path, input_path]
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            if result.returncode == 0:
                return unpacked_path
            return file_path 

        except Exception as e:
            print(f"Unexpected error during UPX unpacking: {e}")
            return file_path
    
    @staticmethod
    def cleanup(unpacked_path: str):
        try:
            folder = os.path.dirname(unpacked_path)
            shutil.rmtree(folder)
            print("Cleanup completed successfully")
        except Exception as e:
            print(f"Error cleaning up: {e}")