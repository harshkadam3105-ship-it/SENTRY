from fastapi import FastAPI

from backend.api.events import router as events_router
from backend.database.connection import Base, engine
from backend.models import Asset, Event, Incident


app = FastAPI(
    title="SENTRY API",
    description="AI-powered multi-signal cyber threat detection backend",
    version="1.0.0",
)


Base.metadata.create_all(bind=engine)


app.include_router(events_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "sentry-backend",
    }