import os
import json
import time
import sqlite3
import yara
from detection.packer_detection import detect_packer
from detection.malconv_detection import MalConvDetector
from reports.yara_report_generator import YaraReportGenerator
from unpacking.unpacker import UnpackFile
from yara_engine.engine import YaraEngine
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH")
GENERATED_RULES_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_rules.db")


def _load_generated_yara_engine() -> YaraEngine | None:
    """Load a YaraEngine from generated_rules.db, return None if empty or missing."""
    if not os.path.isfile(GENERATED_RULES_DB):
        return None
    try:
        with sqlite3.connect(GENERATED_RULES_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rule_content FROM gen_yara_rules")
            rows = cursor.fetchall()
        if not rows:
            return None
        rules_text = "\n".join(row[0] for row in rows)
        if not rules_text.strip():
            return None
        # Compile with same externals as YaraEngine
        externals = {
            'extension': '',
            'filename': '',
            'filepath': '',
            'filetype': '',
            'owner': ''
        }
        compiled = yara.compile(source=rules_text, externals=externals)
        # Create a lightweight wrapper that mimics YaraEngine.scan_file
        engine = object.__new__(YaraEngine)
        engine.rules = compiled
        engine.externals = externals
        return engine
    except Exception:
        return None


class StaticPipeline:
    def __init__(self, file_path: str,
                 yara_ai_explainer: bool = False,
                 use_xai: bool = True,
                 xai_explainer: bool = False,
                 xai_method: str = 'deeplift'):
        """
        Args:
            file_path: Path to the file to analyze.
            yara_ai_explainer: Enable LLM explanation for YARA rule matches.
            use_xai: Enable XAI attribution analysis on MalConv predictions.
            xai_explainer: Enable LLM explanation for XAI attribution results.
            xai_method: XAI method to use ('deeplift', 'lime', etc.).
        """
        self.file_path = os.path.abspath(file_path)
        self.yara_engine = YaraEngine(DB_PATH)
        self.generated_yara_engine = _load_generated_yara_engine()
        self.yara_reporter = YaraReportGenerator(self.file_path, yara_ai_explainer)
        self.malconv_detector = MalConvDetector()
        self.use_xai = use_xai
        self.xai_explainer = xai_explainer & use_xai
        self.xai_method = xai_method

    def process_file(self) -> dict:
        start_time = time.time()

        result = {
            "file": self.file_path,
            "packed": False,
            "unpacked": False,
            "matched": False,
            "match_source": None,  # 'rules.db', 'generated_rules.db', or 'malconv'
            "yara_matches": [],
            "malconv_result": None,
            "xai_result": None,
            "generated_rule": None,
            "status": "benign",
            "error": None,
            "scan_time": 0,
            "report_data": None
        }

        unpacked_path = None

        try:
            # ─── Step 0: Packer detection & unpacking ─────────────────────────
            packer_info = detect_packer(self.file_path)

            if packer_info.get("die_match") or packer_info.get("section_match") or packer_info.get("high_entropy"):
                result["packed"] = True
                unpacked_path = UnpackFile.unpack(self.file_path)
                if unpacked_path and os.path.exists(unpacked_path):
                    result["unpacked"] = True

            file_to_scan = unpacked_path if result["unpacked"] else self.file_path

            # ─── Step 1: Scan with rules.db (curated YARA rules) ──────────────
            matches = self.yara_engine.scan_file(file_to_scan)

            if matches:
                result["matched"] = True
                result["match_source"] = "rules.db"
                result["status"] = "malicious"
                result["yara_matches"] = [m.rule for m in matches]
                self.yara_reporter.add_yara_matches(matches)

                reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_reports")
                os.makedirs(reports_dir, exist_ok=True)
                file_stem = os.path.splitext(os.path.basename(self.file_path))[0]
                report_path = os.path.join(reports_dir, f"{file_stem}_yara_report.json")
                result["report_data"] = self.yara_reporter.generate_json(output_path=report_path)

            else:
                # ─── Step 2: Scan with generated_rules.db ─────────────────────
                gen_matches = []
                if self.generated_yara_engine:
                    gen_matches = self.generated_yara_engine.scan_file(file_to_scan)

                if gen_matches:
                    result["matched"] = True
                    result["match_source"] = "generated_rules.db"
                    result["status"] = "malicious"
                    result["yara_matches"] = [m.rule for m in gen_matches]

                else:
                    # ─── Step 3: MalConv prediction ───────────────────────────
                    malconv_result = self.malconv_detector.predict(file_to_scan)
                    result["malconv_result"] = malconv_result

                    if malconv_result["prediction"] == "malicious":
                        result["matched"] = True
                        result["match_source"] = "malconv"
                        result["status"] = "malicious"

                        # ─── Step 4: XAI + YARA rule generation ───────────────
                        if self.use_xai:
                            xai_result = self._run_xai(file_to_scan)
                            result["xai_result"] = xai_result

                            # Generate and save YARA rule from XAI result
                            if "error" not in xai_result:
                                rule_name = self._generate_and_save_rule(xai_result)
                                result["generated_rule"] = rule_name
                    else:
                        # Benign
                        result["matched"] = False
                        result["status"] = "benign"

        except Exception as e:
            result["error"] = str(e)

        result["scan_time"] = round(time.time() - start_time, 3)
        if unpacked_path:
            UnpackFile.cleanup(unpacked_path)

        return result

    def _run_xai(self, file_path: str) -> dict:
        """Run XAI attribution analysis on the file."""
        try:
            from xai.pipeline import XAIPipeline

            pipeline = XAIPipeline(
                model=self.malconv_detector.model,
                method=self.xai_method,
                top_k=10,
                use_explainer=self.xai_explainer,
            )
            analysis = pipeline.analyze_file(file_path, target_class=None)
            return pipeline.to_json(analysis)
        except Exception as e:
            return {"error": f"XAI analysis failed: {str(e)}"}

    def _generate_and_save_rule(self, xai_result: dict) -> str | None:
        """Generate a YARA rule from XAI result and save to generated_rules.db + .yara file."""
        try:
            from generate_yara_rules import generate_rule_from_result, init_db, GENERATED_RULES_DIR
            from datetime import datetime

            gen = generate_rule_from_result(xai_result)
            if gen is None:
                return None

            rule_text, meta = gen

            # Save to database
            conn = init_db(GENERATED_RULES_DB)
            existing = conn.execute(
                "SELECT id FROM gen_yara_rules WHERE rule_name = ?", (meta["rule_name"],)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE gen_yara_rules SET
                        rule_content = ?, confidence = ?, created_at = ?,
                        num_strings = ?, num_hex_patterns = ?
                    WHERE rule_name = ?
                """, (
                    rule_text, meta["confidence"], datetime.now().isoformat(),
                    meta["num_strings"], meta["num_hex_patterns"], meta["rule_name"],
                ))
            else:
                conn.execute("""
                    INSERT INTO gen_yara_rules (rule_name, file_name, file_hash, method,
                                            confidence, rule_content, created_at,
                                            num_strings, num_hex_patterns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    meta["rule_name"], meta["file_name"], meta["file_hash"],
                    meta["method"], meta["confidence"], rule_text,
                    datetime.now().isoformat(), meta["num_strings"], meta["num_hex_patterns"],
                ))
            conn.commit()
            conn.close()

            # Save as .yara file
            os.makedirs(GENERATED_RULES_DIR, exist_ok=True)
            yara_path = os.path.join(GENERATED_RULES_DIR, f"{meta['rule_name']}.yara")
            with open(yara_path, 'w') as f:
                f.write(rule_text + "\n")

            # Reload the generated rules engine for future scans in this session
            self.generated_yara_engine = _load_generated_yara_engine()

            return meta["rule_name"]
        except Exception as e:
            return None