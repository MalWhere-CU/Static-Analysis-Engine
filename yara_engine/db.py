import sqlite3
from typing import List
from config import DB_PATH

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

