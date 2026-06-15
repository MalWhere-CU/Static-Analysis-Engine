"""
Usage:
    python generate_yara_rules.py                          # Process all XAI results
    python generate_yara_rules.py --input xai_results/deeplift/mal_1.exe.json
    python generate_yara_rules.py --method deeplift        # Only deeplift results
    python generate_yara_rules.py --min-confidence 0.95    # Higher confidence threshold
"""

import os
import sys
import json
import hashlib
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from yara_engine.postgres import SessionLocal, init_db
from yara_engine.models import GeneratedRule


# ─── Configuration / Thresholds ───────────────────────────────────────────────

MIN_CONFIDENCE = 0.90
MIN_ATTRIBUTION_SCORE = 0.20
MIN_STRING_LENGTH = 6
MAX_REGIONS = 5
MAX_HEX_BYTES = 64
MIN_HEX_BYTES = 16
FILESIZE_MULTIPLIER = 3
MAX_STRINGS_PER_RULE = 10

GENERIC_STRINGS = {
    "Microsoft", "Windows", "Copyright", "Version", "Assembly",
    "System", "Runtime", "mscorlib", "kernel32", "ntdll",
    "This program", "DOS mode", "Rich", ".text", ".data",
    ".rsrc", ".reloc", ".rdata", "<?xml", "utf-8", "UTF-8",
    "xmlns", "requestedExecutionLevel", "asInvoker", "manifestVersion",
    "urn:schemas-microsoft-com", "requestedPrivileges", "assembly",
    "v2.0.50727", "v4.0.30319", "BSJB",
}

HEX_PREFERRED_SECTIONS = {".text", ".reloc", "OVERLAY", ".data", "SECTION_GAP"}

# ─── Directories ──────────────────────────────────────────────────────────────

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
XAI_RESULTS_DIR = PROJECT_ROOT / "data" / "xai_results"
GENERATED_RULES_DIR = PROJECT_ROOT / "yara" / "generated_rules"

XAI_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
GENERATED_RULES_DIR.mkdir(parents=True, exist_ok=True)

# ─── String Filtering ─────────────────────────────────────────────────────────

def is_useful_string(s: str) -> bool:
    if len(s) < MIN_STRING_LENGTH:
        return False
    for generic in GENERIC_STRINGS:
        if generic.lower() in s.lower():
            return False
    if not re.search(r'[a-zA-Z0-9]', s):
        return False
    if len(s) < 8 and s.isalnum():
        return False
    return True


def escape_yara_string(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s


# ─── Hex Pattern Extraction ──────────────────────────────────────────────────

def format_hex_pattern(hex_str: str, max_bytes: int = MAX_HEX_BYTES) -> Optional[str]:
    hex_str = hex_str[:max_bytes * 2]
    if len(hex_str) < MIN_HEX_BYTES * 2:
        return None
    pairs = [hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)]
    return " ".join(pairs)


# ─── Rule Generation ─────────────────────────────────────────────────────────

def generate_rule_from_result(result: Dict[str, Any]) -> Optional[str]:
    pred_class = result.get("predicted_class", "")
    if pred_class != "malicious":
        return None

    confidence = result.get("confidence", 0)
    if confidence < MIN_CONFIDENCE:
        return None

    pe_mapping = result.get("pe_mapping")
    if not pe_mapping or "error" in pe_mapping:
        return None

    region_mappings = pe_mapping.get("region_mappings", [])
    if not region_mappings:
        return None

    top_regions = result.get("top_regions", [])

    qualified_regions = []
    for i, region in enumerate(top_regions[:MAX_REGIONS]):
        if region.get("score", 0) >= MIN_ATTRIBUTION_SCORE and region.get("direction") == "malicious":
            if i < len(region_mappings):
                qualified_regions.append((region, region_mappings[i]))

    if not qualified_regions:
        return None

    string_patterns = []
    hex_patterns = []
    import_patterns = []

    for idx, (region, mapping) in enumerate(qualified_regions):
        score = region["score"]
        section_name = mapping.get("section", {}).get("name", "UNKNOWN") if mapping.get("section") else "UNKNOWN"

        strings = mapping.get("strings", [])
        for s_entry in strings:
            s_value = s_entry.get("value", "")
            if is_useful_string(s_value):
                s_value = s_value[:100]
                encoding = s_entry.get("encoding", "ascii")
                string_patterns.append((s_value, encoding, score))

        imports = mapping.get("imports", [])
        for imp in imports:
            func_name = imp.get("function", "")
            if func_name and len(func_name) >= 4 and not func_name.startswith("ord_"):
                import_patterns.append((func_name, score))

        raw_hex = mapping.get("raw_hex", "")
        if raw_hex and (section_name in HEX_PREFERRED_SECTIONS or not strings):
            hex_pat = format_hex_pattern(raw_hex)
            if hex_pat:
                hex_patterns.append((hex_pat, score, section_name))

    total_indicators = len(string_patterns) + len(hex_patterns) + len(import_patterns)
    if total_indicators == 0:
        return None

    file_name = result.get("file_name", os.path.basename(result.get("file", "unknown")))
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', file_name.rsplit('.', 1)[0])
    method = result.get("method", "xai")
    file_path = result.get("file", "")
    if os.path.isfile(file_path):
        with open(file_path, 'rb') as f:
            file_hash_full = hashlib.sha256(f.read()).hexdigest()
    else:
        file_hash_full = hashlib.sha256(file_name.encode()).hexdigest()
    hash_prefix = file_hash_full[:8]
    rule_name = f"MAL_{safe_name}_{hash_prefix}_{method}"

    file_size = result.get("file_size", 0)
    max_filesize = file_size * FILESIZE_MULTIPLIER if file_size else 0

    file_hash = file_hash_full

    # ─── Assemble rule ────────────────────────────────────────────────────────
    explanation = result["llm_explanation"]

    description = (
        f"{explanation['summary']} "
        f"Risk Assessment: {explanation['risk_assessment']} "
        f"Key Indicators: {'; '.join(explanation['key_indicators'])}. "
        f"Confidence: {explanation['confidence_note']}"
    )

    rule_lines = []
    rule_lines.append(f"rule {rule_name} {{")

    rule_lines.append("    meta:")
    rule_lines.append(f'        description = "This is an auto-generated rule from MalConv2 XAI attribution ({method}). {description}"')
    rule_lines.append(f'        author = "MalWhere Static Analysis Engine"')
    rule_lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')
    rule_lines.append(f'        confidence = "{confidence:.4f}"')
    if file_hash:
        rule_lines.append(f'        hash1 = "{file_hash}"')
    rule_lines.append(f'        source_file = "{file_name}"')

    rule_lines.append("")
    rule_lines.append("    strings:")

    str_count = 0
    hex_count = 0
    imp_count = 0

    string_patterns.sort(key=lambda x: x[2], reverse=True)
    import_patterns.sort(key=lambda x: x[1], reverse=True)
    hex_patterns.sort(key=lambda x: x[1], reverse=True)

    for s_value, encoding, score in string_patterns[:MAX_STRINGS_PER_RULE]:
        str_count += 1
        escaped = escape_yara_string(s_value)
        modifier = " wide" if encoding == "unicode" else ""
        rule_lines.append(f'        $s{str_count} = "{escaped}"{modifier}  // score={score:.4f}')

    for func_name, score in import_patterns[:5]:
        imp_count += 1
        escaped = escape_yara_string(func_name)
        rule_lines.append(f'        $i{imp_count} = "{escaped}" ascii  // import, score={score:.4f}')

    for hex_pat, score, section in hex_patterns[:3]:
        hex_count += 1
        rule_lines.append(f'        $h{hex_count} = {{ {hex_pat} }}  // {section}, score={score:.4f}')

    total_patterns = str_count + hex_count + imp_count
    rule_lines.append("")
    rule_lines.append("    condition:")

    conditions = []
    conditions.append("uint16(0) == 0x5a4d")

    if max_filesize:
        if max_filesize >= 1024 * 1024:
            conditions.append(f"filesize < {max_filesize // (1024*1024)}MB")
        elif max_filesize >= 1024:
            conditions.append(f"filesize < {max_filesize // 1024}KB")
        else:
            conditions.append(f"filesize < {max_filesize}")

    if total_patterns <= 2:
        conditions.append("all of them")
    elif total_patterns <= 4:
        match_count = max(2, total_patterns - 1)
        conditions.append(f"{match_count} of them")
    else:
        match_count = max(3, int(total_patterns * 0.6))
        conditions.append(f"{match_count} of them")

    rule_lines.append("        " + " and\n        ".join(conditions))
    rule_lines.append("}")

    return "\n".join(rule_lines), {
        "rule_name": rule_name,
        "file_name": file_name,
        "file_hash": file_hash,
        "method": method,
        "confidence": confidence,
        "num_strings": str_count + imp_count,
        "num_hex_patterns": hex_count,
    }

def generate_and_save_rule(xai_result: dict) -> str | None:
    try:
        gen = generate_rule_from_result(xai_result)
        if gen is None:
            return None

        rule_text, meta = gen

        init_db()
        db = SessionLocal()
        try:
            existing = db.query(GeneratedRule).filter(
                GeneratedRule.rule_name == meta["rule_name"]
            ).first()

            if existing:
                existing.rule_content = rule_text
                existing.confidence = meta["confidence"]
                existing.created_at = datetime.now().isoformat()
                existing.num_strings = meta["num_strings"]
                existing.num_hex_patterns = meta["num_hex_patterns"]
            else:
                db.add(GeneratedRule(
                    rule_name=meta["rule_name"],
                    file_name=meta["file_name"],
                    file_hash=meta["file_hash"],
                    method=meta["method"],
                    confidence=meta["confidence"],
                    rule_content=rule_text,
                    created_at=datetime.now().isoformat(),
                    num_strings=meta["num_strings"],
                    num_hex_patterns=meta["num_hex_patterns"],
                ))
            db.commit()
        finally:
            db.close()

        os.makedirs(GENERATED_RULES_DIR, exist_ok=True)
        yara_path = os.path.join(GENERATED_RULES_DIR, f"{meta['rule_name']}.yara")
        with open(yara_path, 'w') as f:
            f.write(rule_text + "\n")

        return meta["rule_name"]
    except Exception as e:
        return None

# ─── Main ────────────────────────────────────────────────────────────────────

def process_json_file(json_path: str, db: SessionLocal = None) -> Optional[str]:
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        with open(json_path, 'r') as f:
            result = json.load(f)

        gen = generate_rule_from_result(result)
        if gen is None:
            return None

        rule_text, meta = gen

        existing = db.query(GeneratedRule).filter(
            GeneratedRule.rule_name == meta["rule_name"]
        ).first()

        if existing:
            existing.rule_content = rule_text
            existing.confidence = meta["confidence"]
            existing.created_at = datetime.now().isoformat()
            existing.num_strings = meta["num_strings"]
            existing.num_hex_patterns = meta["num_hex_patterns"]
        else:
            db.add(GeneratedRule(
                rule_name=meta["rule_name"],
                file_name=meta["file_name"],
                file_hash=meta["file_hash"],
                method=meta["method"],
                confidence=meta["confidence"],
                rule_content=rule_text,
                created_at=datetime.now().isoformat(),
                num_strings=meta["num_strings"],
                num_hex_patterns=meta["num_hex_patterns"],
            ))

        db.commit()

        os.makedirs(GENERATED_RULES_DIR, exist_ok=True)
        yara_path = os.path.join(GENERATED_RULES_DIR, f"{meta['rule_name']}.yara")
        with open(yara_path, 'w') as f:
            f.write(rule_text + "\n")

        return meta["rule_name"]
    finally:
        if own_session:
            db.close()


def main():
    import argparse
    global MIN_CONFIDENCE

    parser = argparse.ArgumentParser(description="Generate YARA rules from XAI attribution results")
    parser.add_argument("--input", type=str, help="Path to a specific JSON result file")
    parser.add_argument("--method", type=str, help="Only process results from this XAI method")
    parser.add_argument("--min-confidence", type=float, default=MIN_CONFIDENCE,
                        help=f"Minimum confidence threshold (default: {MIN_CONFIDENCE})")
    parser.add_argument("--list", action="store_true", help="List all stored rules")
    parser.add_argument("--export", type=str, help="Export all rules to a directory as .yar files")
    args = parser.parse_args()

    MIN_CONFIDENCE = args.min_confidence

    init_db()
    db = SessionLocal()

    try:
        if args.list:
            rows = db.query(GeneratedRule).order_by(GeneratedRule.created_at.desc()).all()
            if not rows:
                print("[*] No rules in database.")
            else:
                print(f"{'Rule Name':<40} {'File':<25} {'Method':<12} {'Conf':<8} {'Created'}")
                print("-" * 100)
                for row in rows:
                    print(f"{row.rule_name:<40} {row.file_name:<25} {row.method:<12} {row.confidence:<8.4f} {row.created_at}")
            return

        if args.export:
            os.makedirs(args.export, exist_ok=True)
            rows = db.query(GeneratedRule).all()
            for row in rows:
                out_path = os.path.join(args.export, f"{row.rule_name}.yar")
                with open(out_path, 'w') as f:
                    f.write(row.rule_content + "\n")
                print(f"  Exported: {out_path}")
            print(f"\n[*] Exported {len(rows)} rules to {args.export}/")
            return

        json_files = []

        if args.input:
            if not os.path.isfile(args.input):
                print(f"[!] File not found: {args.input}")
                sys.exit(1)
            json_files.append(args.input)
        else:
            if not os.path.isdir(XAI_RESULTS_DIR):
                print(f"[!] XAI results directory not found: {XAI_RESULTS_DIR}")
                sys.exit(1)

            for method_dir in sorted(os.listdir(XAI_RESULTS_DIR)):
                method_path = os.path.join(XAI_RESULTS_DIR, method_dir)
                if not os.path.isdir(method_path):
                    continue
                if args.method and method_dir != args.method:
                    continue
                for json_file in sorted(os.listdir(method_path)):
                    if json_file.endswith('.json'):
                        json_files.append(os.path.join(method_path, json_file))

        if not json_files:
            print("[!] No JSON result files found to process.")
            sys.exit(1)

        print("=" * 60)
        print("  YARA Rule Generator from XAI Attribution")
        print("=" * 60)
        print(f"  Min confidence: {MIN_CONFIDENCE}")
        print(f"  Min attribution score: {MIN_ATTRIBUTION_SCORE}")
        print(f"  Database: PostgreSQL")
        print(f"  Files to process: {len(json_files)}")
        print()

        generated = 0
        skipped = 0

        for json_path in json_files:
            rel_path = os.path.relpath(json_path, os.path.dirname(os.path.abspath(__file__)))
            rule_name = process_json_file(json_path, db)
            if rule_name:
                print(f"  [+] Generated: {rule_name}")
                print(f"      Source: {rel_path}")
                generated += 1
            else:
                print(f"  [-] Skipped (benign/low-conf): {rel_path}")
                skipped += 1

        print(f"\n{'─' * 60}")
        print(f"  Generated: {generated} rules")
        print(f"  Skipped:   {skipped} files")
        print(f"  Database:  PostgreSQL")

        if generated > 0:
            print(f"\n{'─' * 60}")
            print("  Generated Rules Preview:")
            rows = (
                db.query(GeneratedRule)
                .order_by(GeneratedRule.created_at.desc())
                .limit(generated)
                .all()
            )
            for row in rows:
                print(f"\n{'─' * 60}")
                print(row.rule_content)
    finally:
        db.close()


if __name__ == "__main__":
    main()
