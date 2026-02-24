import yara
import os
from yara_engine.db import get_enabled_rules

class YaraEngine:
    def __init__(self, db_path: str):
        rules_text = "\n".join(get_enabled_rules(db_path))

        if not rules_text.strip():
            raise RuntimeError("No enabled YARA rules found in database.")

        # YARA rules reference: Neo23x0 / signature_based repository
        # Define the external variables that Loki/Thor rules usually expect
        # We initialize them with empty/default values
        self.externals = {
            'extension': '',
            'filename': '',
            'filepath': '',
            'filetype': '',
            'owner': ''
        }

        try:
            self.rules = yara.compile(source=rules_text, externals=self.externals)
        except yara.SyntaxError as e:
            print(f"Compilation Error: {e}")
            raise

    def scan_file(self, file_path: str) -> list[str]:
        ext = os.path.splitext(file_path)[1]
        fname = os.path.basename(file_path)
        
        current_vars = {
            'extension': ext,
            'filename': fname,
            'filepath': file_path,
            'filetype': ext.replace('.', ''),
            'owner': 'unknown'
        }

        matches = self.rules.match(file_path, externals=current_vars)
        return [match.rule for match in matches]