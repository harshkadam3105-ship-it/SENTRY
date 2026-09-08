import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DEFAULT_URL = "postgresql://sentry:sentry_pass@localhost:5432/sentry_db"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_URL)

try:
    if DATABASE_URL.startswith("postgresql"):
        # Test connection with short timeout to prevent hang if local Postgres isn't running
        engine = create_engine(DATABASE_URL, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            pass
    else:
        engine = create_engine(DATABASE_URL)
except Exception:
    # Graceful fallback to SQLite for local development without active Postgres
    DATABASE_URL = "sqlite:///./sentry.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """FastAPI dependency — yields a DB session, always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
