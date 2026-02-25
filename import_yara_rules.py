import os
from dotenv import load_dotenv
from yara_engine.db import insert_rule

load_dotenv()
DB_PATH = os.getenv("DB_PATH")

def import_rules_from_directory(directory_path: str):
    """
    Scans a directory for YARA files and inserts them into the database.
    """
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        return

    imported_count = 0
    
    for filename in os.listdir(directory_path):
        if filename.endswith((".yar", ".yara", ".yr")):
            file_path = os.path.join(directory_path, filename)
            
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    rule_content = f.read()
                
                rule_display_name = os.path.splitext(filename)[0]
                
                insert_rule(
                    db_path=DB_PATH, 
                    rule_name=rule_display_name, 
                    rule_text=rule_content, 
                    enabled=1
                )
                
                print(f"Imported: {filename}")
                imported_count += 1
                
            except Exception as e:
                print(f"Failed to import {filename}: {e}")

    print(f"\nFinished! Successfully imported/updated {imported_count} rules")

import_rules_from_directory("rules")