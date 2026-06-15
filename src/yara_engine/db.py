from typing import List, Optional
from sqlalchemy.orm import Session
from yara_engine.postgres import SessionLocal
from yara_engine.models import Rule, GeneratedRule


def get_enabled_rules(db: Session = None) -> List[str]:
    """Fetches all rules where enabled is True."""
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        rows = db.query(Rule.rule_text).filter(Rule.enabled == True).all()
        return [row[0] for row in rows]
    finally:
        if own_session:
            db.close()


def get_generated_rules(db: Session = None) -> List[str]:
    """Fetches all generated rule text."""
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        rows = db.query(GeneratedRule.rule_content).all()
        return [row[0] for row in rows]
    finally:
        if own_session:
            db.close()


def insert_rule(rule_name: str, rule_text: str, enabled: bool = True):
    """Inserts a new rule or updates an existing one by name."""
    db = SessionLocal()
    try:
        existing = db.query(Rule).filter(Rule.name == rule_name).first()
        if existing:
            existing.rule_text = rule_text
            existing.enabled = enabled
        else:
            db.add(Rule(name=rule_name, rule_text=rule_text, enabled=enabled))
        db.commit()
    finally:
        db.close()


def remove_rule(rule_name: str) -> bool:
    """Permanently deletes a rule from the database by its name."""
    db = SessionLocal()
    try:
        deleted = db.query(Rule).filter(Rule.name == rule_name).delete()
        db.commit()
        return deleted > 0
    finally:
        db.close()


def toggle_rule(rule_name: str, enable: bool = True):
    """Sets the enabled status of a rule without deleting the text."""
    db = SessionLocal()
    try:
        db.query(Rule).filter(Rule.name == rule_name).update({"enabled": enable})
        db.commit()
    finally:
        db.close()


def get_rule_text_by_name(rule_name: str) -> Optional[str]:
    """Fetches rule text by name."""
    db = SessionLocal()
    try:
        row = db.query(Rule.rule_text).filter(Rule.name == rule_name).first()
        return row[0] if row else None
    finally:
        db.close()