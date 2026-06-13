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
import sqlite3
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


# ─── Configuration / Thresholds ───────────────────────────────────────────────

MIN_CONFIDENCE = 0.90          # Only generate rules for high-confidence malicious predictions
MIN_ATTRIBUTION_SCORE = 0.20   # Minimum region score to include
MIN_STRING_LENGTH = 6          # Minimum string length to use in rule
MAX_REGIONS = 5                # Max top regions to consider
MAX_HEX_BYTES = 64             # Max hex bytes to extract from a region
MIN_HEX_BYTES = 16             # Minimum hex bytes for a hex pattern
FILESIZE_MULTIPLIER = 3        # Rule filesize cap = sample_size * this
MAX_STRINGS_PER_RULE = 10      # Maximum number of string patterns per rule

# Strings that are too generic / common in benign PE files
GENERIC_STRINGS = {
    "Microsoft", "Windows", "Copyright", "Version", "Assembly",
    "System", "Runtime", "mscorlib", "kernel32", "ntdll",
    "This program", "DOS mode", "Rich", ".text", ".data",
    ".rsrc", ".reloc", ".rdata", "<?xml", "utf-8", "UTF-8",
    "xmlns", "requestedExecutionLevel", "asInvoker", "manifestVersion",
    "urn:schemas-microsoft-com", "requestedPrivileges", "assembly",
    "v2.0.50727", "v4.0.30319", "BSJB",
}

# Sections where hex patterns are most useful (code/packed data)
HEX_PREFERRED_SECTIONS = {".text", ".reloc", "OVERLAY", ".data", "SECTION_GAP"}

# ─── Database ─────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_rules.db")
XAI_RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xai_results")
GENERATED_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_rules")


def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database for storing generated YARA rules."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gen_yara_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_hash TEXT,
            method TEXT NOT NULL,
            confidence REAL NOT NULL,
            rule_content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            num_strings INTEGER,
            num_hex_patterns INTEGER
        )
    """)
    conn.commit()
    return conn


# ─── String Filtering ─────────────────────────────────────────────────────────

def is_useful_string(s: str) -> bool:
    """Check if a string is useful for a YARA rule (not generic)."""
    if len(s) < MIN_STRING_LENGTH:
        return False
    # Skip if it matches a generic string
    for generic in GENERIC_STRINGS:
        if generic.lower() in s.lower():
            return False
    # Skip pure whitespace or punctuation-only
    if not re.search(r'[a-zA-Z0-9]', s):
        return False
    # Skip very short alphanumeric-only (too common)
    if len(s) < 8 and s.isalnum():
        return False
    return True


def escape_yara_string(s: str) -> str:
    """Escape a string for use in a YARA rule."""
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s


# ─── Hex Pattern Extraction ──────────────────────────────────────────────────

def format_hex_pattern(hex_str: str, max_bytes: int = MAX_HEX_BYTES) -> Optional[str]:
    """Format a hex string into a YARA hex pattern."""
    # Take only up to max_bytes worth of hex
    hex_str = hex_str[:max_bytes * 2]
    if len(hex_str) < MIN_HEX_BYTES * 2:
        return None
    # Format as space-separated byte pairs
    pairs = [hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)]
    return " ".join(pairs)


# ─── Rule Generation ─────────────────────────────────────────────────────────

def generate_rule_from_result(result: Dict[str, Any]) -> Optional[str]:
    """
    Generate a YARA rule from a single XAI analysis result JSON.

    Returns the rule text or None if the result doesn't qualify.
    """
    # Check prediction is malicious
    pred_class = result.get("predicted_class", "")
    if pred_class != "malicious":
        return None

    # Check confidence threshold
    confidence = result.get("confidence", 0)
    if confidence < MIN_CONFIDENCE:
        return None

    # Get PE mapping
    pe_mapping = result.get("pe_mapping")
    if not pe_mapping or "error" in pe_mapping:
        return None

    region_mappings = pe_mapping.get("region_mappings", [])
    if not region_mappings:
        return None

    # Get top regions (already sorted by score in the output)
    top_regions = result.get("top_regions", [])

    # Filter regions by score and direction
    qualified_regions = []
    for i, region in enumerate(top_regions[:MAX_REGIONS]):
        if region.get("score", 0) >= MIN_ATTRIBUTION_SCORE and region.get("direction") == "malicious":
            # Find matching region mapping
            if i < len(region_mappings):
                qualified_regions.append((region, region_mappings[i]))

    if not qualified_regions:
        return None

    # Extract strings and hex patterns
    string_patterns = []  # (variable_name, value, encoding, score)
    hex_patterns = []     # (variable_name, hex_pattern, score)
    import_patterns = []  # (variable_name, import_string, score)

    for idx, (region, mapping) in enumerate(qualified_regions):
        score = region["score"]
        section_name = mapping.get("section", {}).get("name", "UNKNOWN") if mapping.get("section") else "UNKNOWN"

        # Extract strings from this region
        strings = mapping.get("strings", [])
        for s_entry in strings:
            s_value = s_entry.get("value", "")
            if is_useful_string(s_value):
                # Truncate very long strings
                s_value = s_value[:100]
                encoding = s_entry.get("encoding", "ascii")
                string_patterns.append((s_value, encoding, score))

        # Extract imports
        imports = mapping.get("imports", [])
        for imp in imports:
            func_name = imp.get("function", "")
            if func_name and len(func_name) >= 4 and not func_name.startswith("ord_"):
                import_patterns.append((func_name, score))

        # Extract hex patterns (prefer from code/packed sections, or if no strings found)
        raw_hex = mapping.get("raw_hex", "")
        if raw_hex and (section_name in HEX_PREFERRED_SECTIONS or not strings):
            hex_pat = format_hex_pattern(raw_hex)
            if hex_pat:
                hex_patterns.append((hex_pat, score, section_name))

    # Build rule if we have enough indicators
    total_indicators = len(string_patterns) + len(hex_patterns) + len(import_patterns)
    if total_indicators == 0:
        return None

    # Generate unique rule name using file hash prefix
    file_name = result.get("file_name", os.path.basename(result.get("file", "unknown")))
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', file_name.rsplit('.', 1)[0])
    method = result.get("method", "xai")
    # Use SHA256 of file content (or file path) to ensure uniqueness
    file_path = result.get("file", "")
    if os.path.isfile(file_path):
        with open(file_path, 'rb') as f:
            file_hash_full = hashlib.sha256(f.read()).hexdigest()
    else:
        file_hash_full = hashlib.sha256(file_name.encode()).hexdigest()
    hash_prefix = file_hash_full[:8]
    rule_name = f"MAL_{safe_name}_{hash_prefix}_{method}"

    # Get file size for condition
    file_size = result.get("file_size", 0)
    max_filesize = file_size * FILESIZE_MULTIPLIER if file_size else 0

    # Use already-computed file hash
    file_hash = file_hash_full

    # ─── Assemble rule ────────────────────────────────────────────────────────

    rule_lines = []
    rule_lines.append(f"rule {rule_name} {{")

    # Meta section
    rule_lines.append("    meta:")
    rule_lines.append(f'        description = "Auto-generated rule from MalConv2 XAI attribution ({method})"')
    rule_lines.append(f'        author = "MalWhere Static Analysis Engine"')
    rule_lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')
    rule_lines.append(f'        confidence = "{confidence:.4f}"')
    if file_hash:
        rule_lines.append(f'        hash1 = "{file_hash}"')
    rule_lines.append(f'        source_file = "{file_name}"')

    # Strings section
    rule_lines.append("")
    rule_lines.append("    strings:")

    str_count = 0
    hex_count = 0
    imp_count = 0

    # Sort strings by attribution score (highest first)
    string_patterns.sort(key=lambda x: x[2], reverse=True)
    import_patterns.sort(key=lambda x: x[1], reverse=True)
    hex_patterns.sort(key=lambda x: x[1], reverse=True)

    # Add string patterns
    for s_value, encoding, score in string_patterns[:MAX_STRINGS_PER_RULE]:
        str_count += 1
        escaped = escape_yara_string(s_value)
        modifier = " wide" if encoding == "unicode" else ""
        rule_lines.append(f'        $s{str_count} = "{escaped}"{modifier}  // score={score:.4f}')

    # Add import patterns
    for func_name, score in import_patterns[:5]:
        imp_count += 1
        escaped = escape_yara_string(func_name)
        rule_lines.append(f'        $i{imp_count} = "{escaped}" ascii  // import, score={score:.4f}')

    # Add hex patterns
    for hex_pat, score, section in hex_patterns[:3]:
        hex_count += 1
        rule_lines.append(f'        $h{hex_count} = {{ {hex_pat} }}  // {section}, score={score:.4f}')

    # Condition section
    total_patterns = str_count + hex_count + imp_count
    rule_lines.append("")
    rule_lines.append("    condition:")

    conditions = []
    conditions.append("uint16(0) == 0x5a4d")

    if max_filesize:
        # Format filesize nicely
        if max_filesize >= 1024 * 1024:
            conditions.append(f"filesize < {max_filesize // (1024*1024)}MB")
        elif max_filesize >= 1024:
            conditions.append(f"filesize < {max_filesize // 1024}KB")
        else:
            conditions.append(f"filesize < {max_filesize}")

    # Determine match threshold
    if total_patterns <= 2:
        conditions.append("all of them")
    elif total_patterns <= 4:
        match_count = max(2, total_patterns - 1)
        conditions.append(f"{match_count} of them")
    else:
        # Require ~60% match
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


# ─── Main ────────────────────────────────────────────────────────────────────

def process_json_file(json_path: str, conn: sqlite3.Connection) -> Optional[str]:
    """Process a single XAI result JSON file and store the generated rule."""
    with open(json_path, 'r') as f:
        result = json.load(f)

    gen = generate_rule_from_result(result)
    if gen is None:
        return None

    rule_text, meta = gen

    # Check if rule already exists
    existing = conn.execute(
        "SELECT id FROM gen_yara_rules WHERE rule_name = ?", (meta["rule_name"],)
    ).fetchone()

    if existing:
        # Update existing rule
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

    # Save as .yara file in generated_rules/ folder
    os.makedirs(GENERATED_RULES_DIR, exist_ok=True)
    yara_path = os.path.join(GENERATED_RULES_DIR, f"{meta['rule_name']}.yara")
    with open(yara_path, 'w') as f:
        f.write(rule_text + "\n")

    return meta["rule_name"]


def main():
    import argparse
    global MIN_CONFIDENCE

    parser = argparse.ArgumentParser(description="Generate YARA rules from XAI attribution results")
    parser.add_argument("--input", type=str, help="Path to a specific JSON result file")
    parser.add_argument("--method", type=str, help="Only process results from this XAI method")
    parser.add_argument("--min-confidence", type=float, default=MIN_CONFIDENCE,
                        help=f"Minimum confidence threshold (default: {MIN_CONFIDENCE})")
    parser.add_argument("--db", type=str, default=DB_PATH,
                        help=f"Database path (default: {DB_PATH})")
    parser.add_argument("--list", action="store_true", help="List all stored rules")
    parser.add_argument("--export", type=str, help="Export all rules to a directory as .yar files")
    args = parser.parse_args()

    # Override global threshold
    
    MIN_CONFIDENCE = args.min_confidence

    # Initialize database
    conn = init_db(args.db)

    if args.list:
        rows = conn.execute(
            "SELECT rule_name, file_name, method, confidence, created_at FROM gen_yara_rules ORDER BY created_at DESC"
        ).fetchall()
        if not rows:
            print("[*] No rules in database.")
        else:
            print(f"{'Rule Name':<40} {'File':<25} {'Method':<12} {'Conf':<8} {'Created'}")
            print("-" * 100)
            for row in rows:
                print(f"{row[0]:<40} {row[1]:<25} {row[2]:<12} {row[3]:<8.4f} {row[4]}")
        conn.close()
        return

    if args.export:
        os.makedirs(args.export, exist_ok=True)
        rows = conn.execute("SELECT rule_name, rule_content FROM gen_yara_rules").fetchall()
        for rule_name, rule_content in rows:
            out_path = os.path.join(args.export, f"{rule_name}.yar")
            with open(out_path, 'w') as f:
                f.write(rule_content + "\n")
            print(f"  Exported: {out_path}")
        print(f"\n[*] Exported {len(rows)} rules to {args.export}/")
        conn.close()
        return

    # Collect JSON files to process
    json_files = []

    if args.input:
        if not os.path.isfile(args.input):
            print(f"[!] File not found: {args.input}")
            sys.exit(1)
        json_files.append(args.input)
    else:
        # Scan xai_results directory
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
    print(f"  Database: {args.db}")
    print(f"  Files to process: {len(json_files)}")
    print()

    generated = 0
    skipped = 0

    for json_path in json_files:
        rel_path = os.path.relpath(json_path, os.path.dirname(os.path.abspath(__file__)))
        rule_name = process_json_file(json_path, conn)
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
    print(f"  Database:  {args.db}")

    # Show generated rules
    if generated > 0:
        print(f"\n{'─' * 60}")
        print("  Generated Rules Preview:")
        rows = conn.execute(
            "SELECT rule_name, rule_content FROM gen_yara_rules ORDER BY created_at DESC LIMIT ?",
            (generated,)
        ).fetchall()
        for rule_name, rule_content in rows:
            print(f"\n{'─' * 60}")
            print(rule_content)

    conn.close()


if __name__ == "__main__":
    main()
