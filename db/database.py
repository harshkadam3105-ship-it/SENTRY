from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Swap this for SQLite if Postgres/Docker isn't ready yet:
# DATABASE_URL = "sqlite:///./sentinelx.db"
DATABASE_URL = "postgresql://user:password@localhost:5432/sentinelx"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """FastAPI dependency — yields a DB session, always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
