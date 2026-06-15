import subprocess
import os
import tempfile
import shutil
from dotenv import load_dotenv

load_dotenv()
UPX_PATH = os.getenv("UPX_PATH")

class UnpackFile:
    @staticmethod
    def unpack(file_path: str) -> tuple[str, str | None]:
        """
        Uses UPX to unpack a sample.
        Returns a tuple: (path_to_active_file, path_to_temp_dir)
        If unpacking fails, returns (original_file_path, None)
        """
        if not UPX_PATH or not os.path.isfile(UPX_PATH):
            print("Error: UPX_PATH is invalid or not set in .env")
            return file_path, None

        temp_dir = tempfile.mkdtemp()
        
        # Keep the original filename for clarity instead of "putty"
        base_name = os.path.basename(file_path)
        input_path = os.path.join(temp_dir, f"packed_{base_name}")
        unpacked_path = os.path.join(temp_dir, f"unpacked_{base_name}")

        try:
            # Safer and more memory-efficient than read()/write()
            shutil.copy2(file_path, input_path)

            cmd = [UPX_PATH, "-d", "-o", unpacked_path, input_path]
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Check if successful AND if the output file was actually created
            if result.returncode == 0 and os.path.exists(unpacked_path):
                return unpacked_path, temp_dir

            # If UPX failed, clean up the temp dir immediately to avoid leaks
            shutil.rmtree(temp_dir)
            return file_path, None

        except Exception as e:
            print(f"Unexpected error during UPX unpacking: {e}")
            # Clean up on exception
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            return file_path, None
    
    @staticmethod
    def cleanup(temp_dir: str | None):
        """Safely cleans up the temporary directory."""
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                print(f"Cleanup completed successfully for {temp_dir}")
            except Exception as e:
                print(f"Error cleaning up temp directory {temp_dir}: {e}")