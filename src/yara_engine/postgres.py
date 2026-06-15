import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://yara_user:yara_pass@localhost:5432/yara_db"
)
DATABASE_URL = DATABASE_URL.strip('"').strip("'")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from yara_engine.models import Rule, GeneratedRule  # noqa: F401
    Base.metadata.create_all(bind=engine)
