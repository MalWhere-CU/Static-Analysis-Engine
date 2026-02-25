import os
import sqlite3
from typing import List
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH")

def get_enabled_rules(db_path: str) -> List[str]:
    """Fetches all rules where enabled is set to 1."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_text FROM rules WHERE enabled = 1")
        rows = cursor.fetchall()
    return [row[0] for row in rows]

def insert_rule(db_path: str, rule_name: str, rule_text: str, enabled: int = 1):
    """Inserts a new rule or updates an existing one by name."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        query = """
            INSERT INTO rules (name, rule_text, enabled) 
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET 
                rule_text=excluded.rule_text, 
                enabled=excluded.enabled
        """
        cursor.execute(query, (rule_name, rule_text, enabled))
        conn.commit()

def remove_rule(db_path: str, rule_name: str):
    """Permanently deletes a rule from the database by its name."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rules WHERE name = ?", (rule_name,))
        conn.commit()
        return cursor.rowcount > 0

def toggle_rule(db_path: str, rule_name: str, enable: bool = True):
    """Sets the enabled status of a rule without deleting the text."""
    status = 1 if enable else 0
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE rules SET enabled = ? WHERE name = ?", (status, rule_name))
        conn.commit()

def get_rule_text_by_name(db_path, rule_name):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_text FROM rules WHERE name = ?", (rule_name,))
        result = cursor.fetchone()
        print(result[0] if result else "No rule found with that name")
        return result[0] if result else None
    

# def get_rule_text_by_name(db_path, rule_name):
#     """Fetches rule text using a case-insensitive name match."""
#     with sqlite3.connect(db_path) as conn:
#         cursor = conn.cursor()
#         # Use COLLATE NOCASE for robustness
#         cursor.execute("SELECT rule_text FROM rules WHERE name = ? COLLATE NOCASE", (rule_name,))
#         result = cursor.fetchone()
        
#         if result:
#             return result[0]
        
#         # Fallback: Try searching for the name inside the rule_text itself 
#         # (Useful if the DB 'name' was set to something else)
#         cursor.execute("SELECT rule_text FROM rules WHERE rule_text LIKE ?", (f"%rule {rule_name}%",))
#         result = cursor.fetchone()
#         return result[0] if result else None