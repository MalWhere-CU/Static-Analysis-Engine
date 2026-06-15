import redis
import os
from dotenv import load_dotenv

from utils.hashes import HashCalculator

load_dotenv()

class YaraExplainerRedisCache:
    def __init__(self):
        self.client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=True
        )
        self.ttl = 86400*7  #7 days

    def get_explanation(self, context: str):
        key = HashCalculator.generate_hash_key(context.encode())
        return self.client.get(key)

    def set_explanation(self, context: str, explanation: str):
        try:
            error_keywords = ["error", "insufficient_quota", "rate limit", "429", "401", "403", "500", "503"]
            if any(word in explanation.lower() for word in error_keywords):
                print("[!] Detected error in AI response. Skipping cache")
                return False

            key = HashCalculator.generate_hash_key(context.encode())
            self.client.setex(key, self.ttl, explanation)
            return True
        except Exception as e:
            print(f"[!] Error setting cache: {e}")
            return False