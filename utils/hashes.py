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