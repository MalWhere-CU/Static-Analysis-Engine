import hashlib

class HashCalculator:
    @staticmethod
    def calculate_md5_hash(file_path):
        with open(file_path, "rb") as f:   
            data = f.read()
            return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def calculate_sha256_hash(file_path):
        with open(file_path, "rb") as f:   
            data = f.read()
            return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_string(text: str):
        return hashlib.md5(text).hexdigest()

    @staticmethod
    def generate_hash_key(context: str):
        return f"yara_expl:{HashCalculator.hash_string(context)}"