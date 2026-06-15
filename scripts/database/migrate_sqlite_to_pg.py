"""
Migration script: Load YARA rules from yara/ directories into PostgreSQL.

Usage:
    python scripts/migrate_sqlite_to_pg.py
"""

import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from yara_engine.postgres import SessionLocal, init_db
from yara_engine.models import Rule, GeneratedRule

IMPORTED_DIR = os.path.join(os.path.dirname(__file__), "..", "yara", "imported_rules")
GENERATED_DIR = os.path.join(os.path.dirname(__file__), "..", "yara", "generated_rules")


def parse_generated_rule_meta(content: str) -> dict:
    """Extract metadata from a generated YARA rule file."""
    meta = {}
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
        if m:
            meta[m.group(1)] = m.group(2)
    return meta


def migrate_imported_rules():
    if not os.path.isdir(IMPORTED_DIR):
        print(f"[!] Directory not found: {IMPORTED_DIR}")
        return 0

    db = SessionLocal()
    count = 0
    for fname in sorted(os.listdir(IMPORTED_DIR)):
        if not fname.endswith((".yar", ".yara")):
            continue

        fpath = os.path.join(IMPORTED_DIR, fname)
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            rule_text = f.read().strip()

        if not rule_text:
            continue

        rule_name = os.path.splitext(fname)[0]

        existing = db.query(Rule).filter(Rule.name == rule_name).first()
        if existing:
            existing.rule_text = rule_text
            existing.enabled = True
        else:
            db.add(Rule(name=rule_name, rule_text=rule_text, enabled=True))
        count += 1

    db.commit()
    db.close()
    print(f"[+] Loaded {count} imported rules from {IMPORTED_DIR}")
    return count


def migrate_generated_rules():
    if not os.path.isdir(GENERATED_DIR):
        print(f"[!] Directory not found: {GENERATED_DIR}")
        return 0

    db = SessionLocal()
    count = 0
    for fname in sorted(os.listdir(GENERATED_DIR)):
        if not fname.endswith((".yar", ".yara")):
            continue

        fpath = os.path.join(GENERATED_DIR, fname)
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            rule_content = f.read().strip()

        if not rule_content:
            continue

        rule_name = os.path.splitext(fname)[0]
        meta = parse_generated_rule_meta(rule_content)

        existing = db.query(GeneratedRule).filter(
            GeneratedRule.rule_name == rule_name
        ).first()

        if existing:
            existing.rule_content = rule_content
            existing.confidence = float(meta.get("confidence", 0))
            existing.file_name = meta.get("source_file", "unknown")
            existing.file_hash = meta.get("hash1", "")
            existing.method = "xai"
            existing.created_at = meta.get("date", datetime.now().isoformat())
        else:
            db.add(GeneratedRule(
                rule_name=rule_name,
                file_name=meta.get("source_file", "unknown"),
                file_hash=meta.get("hash1", ""),
                method="xai",
                confidence=float(meta.get("confidence", 0)),
                rule_content=rule_content,
                created_at=meta.get("date", datetime.now().isoformat()),
                num_strings=0,
                num_hex_patterns=0,
            ))
        count += 1

    db.commit()
    db.close()
    print(f"[+] Loaded {count} generated rules from {GENERATED_DIR}")
    return count


if __name__ == "__main__":
    print("=" * 50)
    print("  YARA Rules → PostgreSQL Migration")
    print("=" * 50)

    init_db()

    imported = migrate_imported_rules()
    generated = migrate_generated_rules()

    print(f"\n  Total: {imported} imported rules, {generated} generated rules")
    print("  Migration complete.")
