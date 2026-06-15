import yara
import os

class YaraEngine:
    def __init__(self, rules_text: str):
        if not rules_text.strip():
            raise ValueError("No YARA rules provided to engine.")

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

        return self.rules.match(file_path, externals=current_vars)