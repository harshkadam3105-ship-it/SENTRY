from fastapi import FastAPI, Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.models.schema import EventIn
from backend.models.db_models import Base, Event, Incident, Asset

DATABASE_URL = "postgresql://user:password@localhost:5432/sentinelx"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency: get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/events")
def ingest_event(event: EventIn, db: Session = Depends(get_db)):
    # Convert Pydantic EventIn to SQLAlchemy Event
    db_event = Event(
        id=event.event_id,
        timestamp=event.timestamp,
        source_type=event.source_type,
        host_id=event.host_id,
        user_id=event.user_id,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        event_type=event.event_type,
        severity=event.severity,
        features=event.features,
        raw_data=event.raw_data
    )
    db.add(db_event)
    db.commit()
    return {"status": "ok", "event_id": str(event.event_id)}
explain code
