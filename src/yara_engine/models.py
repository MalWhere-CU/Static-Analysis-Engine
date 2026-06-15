from sqlalchemy import Column, Integer, String, Text, Boolean, Float
from yara_engine.postgres import Base


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(512), unique=True, nullable=False)
    rule_text = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)


class GeneratedRule(Base):
    __tablename__ = "gen_yara_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_name = Column(String(512), unique=True, nullable=False)
    file_name = Column(String(1024), nullable=False)
    file_hash = Column(String(128))
    method = Column(String(64), nullable=False)
    confidence = Column(Float, nullable=False)
    rule_content = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False)
    num_strings = Column(Integer)
    num_hex_patterns = Column(Integer)
